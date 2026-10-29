#!/usr/bin/env python3
"""仅受审 master 计划可执行正式发布；默认 preflight 只读。"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import time
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

spec = importlib.util.spec_from_file_location('policy', Path(__file__).with_name('release-policy.py'))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

# One reviewed transition; not a permanent workflow/script allowlist. The root reviewer
# approves this execution file itself, including these constants, at its exact final hash.
# This is the existing trusted-master-code boundary, NOT cryptographic self-attestation.
BOOTSTRAP_SOURCE = '489294528319223e4f38a5ec80a2d0192783988e'
BOOTSTRAP_TAG = 'v0.1.1'
EXECUTION_FILE = 'scripts/release-admin.py'
REVIEWED_BOOTSTRAP_BLOBS = {'.github/workflows/admin-web.yml': {'after_blob': 'd40bf6215a290591b70eed10d017ca271743ae2f',
                                     'before_blob': '2aaea8702200604025c406b3894758c9567a625f'},
 '.github/workflows/android.yml': {'after_blob': 'e3c94bcdfa515493f03f5bf6574c0995dcf1cadf',
                                   'before_blob': '98863cf07a8631ecddd9dd5924175eddbd5be7da'},
 '.github/workflows/ci.yml': {'after_blob': 'f4b3acac2f2b83297dd2a7a9350d8a26b2e033fb',
                              'before_blob': 'f89e9a6658a5f6e8e7475549122a7cf8177dc840'},
 '.github/workflows/native.yml': {'after_blob': '9680d45597f958bdb96efd55c4aa620109b75283',
                                  'before_blob': 'bd7293e3526b7087bb382ca90af5d56226f8bbf5'},
 '.github/workflows/release-admin.yml': {'after_blob': '637fe5be5913635194e74bf5c409f973d3e5911d',
                                         'before_blob': '01d5ce8393f98a50d65da89206cc1bc6f6977297'},
 'docs/发布与分支清理模块.md': {'after_blob': 'b6423bc5218cb4f2c6e42b5423f36fce03a27836',
                       'before_blob': 'd34cead23879b2215277330d3191bb848eab0712'},
 'docs/开发与验收.md': {'after_blob': '1a7016e1caf173b314ae172f117ac4f8418d35da',
                   'before_blob': '72eb9acfff21a3da61c4648e74c461cfa5556022'},
 'scripts/release-policy.py': {'after_blob': '377fdbcbfdd1dbb165c8878aa7fa28d80857cd79',
                               'before_blob': '47bd8640145af0ab2b44d3ce56c8f290e797acaf'},
 'scripts/test-release-admin.py': {'after_blob': '2ca4a972ffb492d2257e4e681437630de5bead5c',
                                   'before_blob': '8d50e4dab2d81c7fb3dfafbe094e4703fc0bcebc'},
 'scripts/test-workflow-triggers.py': {'after_blob': '0d313f72f1e76b4afc57317c1f2eae299c399533',
                                       'before_blob': None}}

class Pending(P.Rejected):
    pass

def api_failure_code(endpoint, method, stderr):
    # Only fixed categories and numeric status may cross the diagnostic boundary.
    # Never include request paths, ref names, response bodies or CLI stderr text.
    path = endpoint.split('?', 1)[0].removeprefix('/repos/' + P.REPO)
    if method == 'POST' and path == '/git/refs':
        operation = 'create_git_ref'
    elif method == 'POST' and path == '/releases':
        operation = 'create_release'
    elif method == 'PATCH' and re.fullmatch(r'/releases/[0-9]+', path):
        operation = 'update_release'
    elif method == 'GET' and path.startswith('/git/ref/'):
        operation = 'read_git_ref'
    elif method == 'GET' and path.startswith('/actions/artifacts/'):
        operation = 'read_artifact'
    elif method == 'GET' and path.startswith('/actions/'):
        operation = 'read_workflow'
    elif method == 'GET' and path.startswith('/compare/'):
        operation = 'read_compare'
    elif method == 'GET' and path.startswith('/contents/'):
        operation = 'read_contents'
    elif method == 'GET' and path.startswith('/releases'):
        operation = 'read_release'
    else:
        operation = 'other'
    statuses = set(re.findall(r'\(HTTP ([1-5][0-9]{2})\)', stderr))
    status = next(iter(statuses)) if len(statuses) == 1 else '0'
    return f'GITHUB_API_FAILED operation={operation} method={method} http_status={status}'


class GitHub:
    def call(self, endpoint, method='GET', data=None, missing=False):
        P.require(endpoint.startswith('/repos/' + P.REPO + '/'), 'API_SCOPE')
        P.require(method in ('GET', 'POST', 'PATCH'), 'RELEASE_API_METHOD_FORBIDDEN')
        command = ['gh', 'api', '--hostname', 'github.com', '--method', method, endpoint,
                   '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2022-11-28']
        if data is not None:
            command += ['--input', '-']
        result = subprocess.run(command, input=json.dumps(data) if data is not None else None,
                                text=True, capture_output=True, timeout=120)
        if missing and result.returncode and '(HTTP 404)' in result.stderr:
            return None
        if result.returncode != 0:
            raise P.Rejected(api_failure_code(endpoint, method, result.stderr))
        return json.loads(result.stdout) if result.stdout.strip() else None

    def pages(self, endpoint, key):
        rows = []
        for page in range(1, 101):
            sep = '&' if '?' in endpoint else '?'
            value = self.call(endpoint + f'{sep}per_page=100&page={page}')
            batch = value[key]
            rows.extend(batch)
            if len(batch) < 100:
                return rows
        raise P.Rejected('PAGINATION_LIMIT')

    def download(self, artifact_id, destination):
        endpoint = f'/repos/{P.REPO}/actions/artifacts/{artifact_id}/zip'
        with destination.open('xb') as output:
            process = subprocess.Popen(['gh', 'api', '--hostname', 'github.com', endpoint],
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            try:
                total = 0
                deadline = time.monotonic() + 120
                selector = selectors.DefaultSelector()
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    P.require(remaining > 0 and selector.select(remaining), 'ARTIFACT_DOWNLOAD_TIMEOUT')
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    P.require(total <= P.MAX_ARCHIVE, 'ARTIFACT_DOWNLOAD_LIMIT')
                    output.write(chunk)
                P.require(process.wait(timeout=120) == 0, 'ARTIFACT_DOWNLOAD_FAILED')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)

    def upload(self, release_id, name, path):
        # Fixed host/path: never trust an API-supplied upload_url or follow redirects with token.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        endpoint = f'https://uploads.github.com/repos/{P.REPO}/releases/{release_id}/assets?name=' + urllib.parse.quote(name, safe='')
        request = urllib.request.Request(endpoint, data=path.read_bytes(), method='POST', headers={
            'Authorization': 'Bearer ' + os.environ['GH_TOKEN'], 'Content-Type': 'application/zip',
            'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})
        with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(request, timeout=120) as response:
            return json.load(response)

class Admin:
    def __init__(self, api, plan, master):
        self.api, self.plan, self.master = api, plan, P.sha(master)
        self.base = '/repos/' + P.REPO

    def fresh_master(self):
        value = self.api.call(self.base + '/git/ref/heads/master')
        P.require(value['object']['sha'] == self.master, 'MASTER_MOVED')

    def ancestor(self, older, newer):
        value = self.api.call(self.base + '/compare/' + P.sha(older) + '...' + P.sha(newer))
        return value['status'] in ('ahead', 'identical') and value['merge_base_commit']['sha'] == older

    def gates(self, commit):
        required = P.WORKFLOWS
        chosen = {}
        for workflow in required:
            runs = self.api.pages(self.base + '/actions/workflows/' + workflow + '/runs?head_sha=' + commit + '&event=push', 'workflow_runs')
            # Latest exact-SHA push attempt must pass; no cherry-picking an earlier green after regression.
            if not runs:
                raise Pending('REQUIRED_WORKFLOW_NOT_STARTED')
            run = max(runs, key=lambda r: (r['id'], r.get('run_attempt', 1)))
            if run.get('status') != 'completed':
                raise Pending('REQUIRED_WORKFLOW_PENDING')
            jobs = self.api.pages(self.base + f"/actions/runs/{run['id']}/jobs?filter=latest", 'jobs')
            P.verify_run(run, jobs, workflow, commit)
            chosen[workflow] = run['id']
        return chosen

    def validate(self):
        plan = self.plan
        P.require(plan.get('format_version') == 1 and plan.get('repository') == P.REPO and plan.get('approved') is True, 'UNAPPROVED_PLAN')
        P.require(plan.get('administration_sha') == self.master, 'ADMINISTRATION_SHA_MISMATCH')
        # The administration commit is carried by the event; plans avoid impossible self-hashing via
        # administration_sha="event" in the stored file, resolved only by the trusted CLI below.
        P.require(plan.get('operation') == 'release' and 'branches' not in plan, 'RELEASE_OPERATION_REQUIRED')
        self.fresh_master()
        release_sha = P.sha(plan.get('release_sha'))
        P.require(release_sha != self.master and self.ancestor(release_sha, self.master), 'RELEASE_NOT_PREVIOUS_RETAINED_COMMIT')
        P.require(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', plan.get('tag', '')), 'VERSION_TAG_REQUIRED')
        P.require(type(plan.get('prerelease')) is bool and isinstance(plan.get('notes'), str) and 0 < len(plan['notes']) <= 65536, 'RELEASE_DESCRIPTION_REQUIRED')
        P.require(plan.get('final_scope_accepted') is True, 'FINAL_SCOPE_NOT_ACCEPTED')
        P.require(set(plan.get('artifacts', {})) == set(P.PLATFORMS), 'ALL_PLATFORM_ARTIFACTS_REQUIRED')
        artifact_ids = [item.get('id') for item in plan['artifacts'].values() if isinstance(item, dict)]
        P.require(len(artifact_ids) == len(P.PLATFORMS) and
                  all(type(value) is int and value > 0 for value in artifact_ids) and
                  len(set(artifact_ids)) == len(artifact_ids), 'DISTINCT_PRODUCT_ARTIFACT_IDS_REQUIRED')
        verify_administration_scope(self.api, release_sha, self.master, plan['tag'])
        return self.gates(release_sha)

    def artifacts(self, directory, runs):
        outputs = {}
        commit = self.plan['release_sha']
        for platform, expected in self.plan['artifacts'].items():
            artifact_id = expected.get('id')
            P.require(type(artifact_id) is int and artifact_id > 0, 'ARTIFACT_ID_REQUIRED')
            value = self.api.call(self.base + f'/actions/artifacts/{artifact_id}')
            digest = expected.get('sha256')
            P.require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'ARTIFACT_DIGEST_REQUIRED')
            P.require(value.get('id') == artifact_id and not value.get('expired') and
                      value.get('name') == P.ARTIFACT_PREFIX[platform] + commit and
                      value.get('digest') == 'sha256:' + digest and value.get('workflow_run', {}).get('head_sha') == commit and
                      value.get('workflow_run', {}).get('id') == runs[P.PLATFORMS[platform]], 'WRONG_ARTIFACT')
            output = directory / P.release_asset_name(platform, self.plan['tag'])
            self.api.download(artifact_id, output)
            result = P.verify_zip(output, platform, commit, self.plan['tag'][1:])
            P.require(result['sha256'] == digest and result['size'] == value.get('size_in_bytes'), 'ARTIFACT_DOWNLOAD_MISMATCH')
            outputs[output.name] = (output, result)
        return outputs

    def tag(self, create=False):
        name = self.plan['tag']
        endpoint = self.base + '/git/ref/tags/' + name
        value = self.api.call(endpoint, missing=True)
        if value is None and create:
            self.api.call(self.base + '/git/refs', 'POST', {'ref': 'refs/tags/' + name, 'sha': self.plan['release_sha']})
            value = self.api.call(endpoint)
        if value is not None:
            P.require(value['object'].get('type') == 'commit' and value['object']['sha'] == self.plan['release_sha'], 'TAG_MISMATCH')
        return value

    def release_matches(self, release, outputs, draft, release_id=None, complete=True):
        P.require(release.get('tag_name') == self.plan['tag'] and release.get('body') == self.plan['notes'] and
                  release.get('prerelease') is self.plan['prerelease'] and release.get('draft') is draft and
                  (release_id is None or release.get('id') == release_id), 'RELEASE_METADATA_CHANGED_REQUIRES_REVIEW')
        assets = release.get('assets', [])
        names = [a['name'] for a in assets]
        P.require(len(names) == len(set(names)) and set(names) <= set(outputs), 'UNEXPECTED_RELEASE_ASSET')
        if complete:
            P.require(set(names) == set(outputs), 'INCOMPLETE_RELEASE_ASSETS')
        for asset in assets:
            expected = outputs[asset['name']][1]
            P.require(asset.get('state') == 'uploaded' and asset.get('size') == expected['size'] and
                      asset.get('digest') == 'sha256:' + expected['sha256'], 'RELEASE_ASSET_MISMATCH')

    def publish(self, outputs):
        self.fresh_master()
        self.tag(create=True)
        endpoint = self.base + '/releases/tags/' + self.plan['tag']
        release = self.api.call(endpoint, missing=True)
        if release is not None and release.get('draft') is False:
            self.release_matches(release, outputs, False)
            return  # Exact repeat is a read-only no-op, never overwrite.
        if release is None:
            release = self.api.call(self.base + '/releases', 'POST', {
                'tag_name': self.plan['tag'], 'target_commitish': self.plan['release_sha'],
                'name': self.plan['tag'], 'body': self.plan['notes'], 'prerelease': self.plan['prerelease'], 'draft': True})
        release_id = release['id']
        self.release_matches(release, outputs, True, release_id, complete=False)
        present = {a['name'] for a in release.get('assets', [])}
        for name, (path, _) in outputs.items():
            if name not in present:
                self.api.upload(release_id, name, path)
        self.fresh_master()
        P.require(self.tag() is not None, 'TAG_DISAPPEARED')
        current = self.api.call(self.base + f'/releases/{release_id}')
        self.release_matches(current, outputs, True, release_id)
        self.api.call(self.base + f'/releases/{release_id}', 'PATCH', {'draft': False})
        self.release_matches(self.api.call(self.base + f'/releases/{release_id}'), outputs, False, release_id)
        P.require(self.tag() is not None, 'TAG_DISAPPEARED')


def context(env, event, plan):
    P.require(env.get('GITHUB_EVENT_NAME') == 'push' and env.get('GITHUB_REPOSITORY') == P.REPO and
              env.get('GITHUB_REF') == 'refs/heads/master' and event.get('repository', {}).get('full_name') == P.REPO and
              event.get('ref') == 'refs/heads/master' and event.get('after') == env.get('GITHUB_SHA') and
              not event.get('created') and not event.get('deleted') and not event.get('forced'), 'UNTRUSTED_EVENT')
    commit = P.sha(env.get('GITHUB_SHA'))
    before = P.sha(event.get('before'))
    P.require(before != '0' * 40 and before != commit, 'PUSH_RANGE_REQUIRED')
    P.require(plan.get('administration_sha') == 'event', 'PLAN_EVENT_BINDING_REQUIRED')
    allowed_event_paths = {('administration_sha',)}
    P.require(plan.get('operation') == 'release' and 'branches' not in plan, 'RELEASE_OPERATION_REQUIRED')
    def check_event(value, path=()):
        if isinstance(value, dict):
            for key, child in value.items():
                check_event(child, (*path, key))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                check_event(child, (*path, index))
        elif value == 'event':
            P.require(path in allowed_event_paths, 'EVENT_OUTSIDE_APPROVED_BINDING')
    check_event(plan)
    plan = dict(plan, administration_sha=commit)
    return plan, commit

def candidate_context(env, event, plan):
    P.require(env.get('GITHUB_EVENT_NAME') == 'push' and env.get('GITHUB_REPOSITORY') == P.REPO and
              env.get('GITHUB_REF') == 'refs/heads/feat/validation-release-packaging' and
              event.get('repository', {}).get('full_name') == P.REPO and
              event.get('ref') == env.get('GITHUB_REF') and event.get('after') == env.get('GITHUB_SHA') and
              not event.get('created') and not event.get('deleted') and not event.get('forced'), 'UNTRUSTED_CANDIDATE_EVENT')
    # Reuse all plan/event binding checks without weakening master context().
    master_env = dict(env, GITHUB_REF='refs/heads/master')
    master_event = dict(event, ref='refs/heads/master')
    return context(master_env, master_event, plan)


def comparison_files(api, before, commit):
    # GitHub comparison files are capped at 300, regardless of commit pagination.
    # Refuse the boundary: an incomplete inventory never qualifies for publication.
    before, commit = P.sha(before), P.sha(commit)
    P.require(before != '0' * 40 and before != commit, 'PUSH_RANGE_REQUIRED')
    value = api.call('/repos/' + P.REPO + '/compare/' + before + '...' + commit + '?per_page=100&page=1')
    P.require(value.get('base_commit', {}).get('sha') == before and
              value.get('merge_base_commit', {}).get('sha') == before and
              value.get('status') == 'ahead' and value.get('behind_by') == 0 and
              type(value.get('ahead_by')) is int and value['ahead_by'] > 0 and
              value.get('total_commits') == value['ahead_by'], 'PUSH_NOT_FAST_FORWARD')
    files = value.get('files')
    P.require(isinstance(files, list) and 0 < len(files) < 300, 'COMPARE_FILE_LIST_UNPROVEN')
    P.require(all(isinstance(item, dict) for item in files), 'COMPARE_FILE_LIST_INVALID')
    names = [item.get('filename') for item in files]
    P.require(all(isinstance(name, str) for name in names) and len(names) == len(set(names)), 'COMPARE_FILE_LIST_INVALID')
    return files


def verify_administration_scope(api, source, administration, tag=None):
    # Check the ENTIRE source-to-administration tree difference, not just the last push.
    files = comparison_files(api, source, administration)
    if all(item.get('filename') in P.ADMINISTRATION_FILES for item in files):
        P.verify_administration_files(files)
        return
    P.require(source == BOOTSTRAP_SOURCE and tag == BOOTSTRAP_TAG and
              bool(REVIEWED_BOOTSTRAP_BLOBS), 'ADMINISTRATION_SCOPE_NOT_REVIEWED')
    execution = [item for item in files if item.get('filename') == EXECUTION_FILE]
    P.require(len(execution) == 1 and execution[0].get('status') == 'modified' and
              'previous_filename' not in execution[0], 'REVIEWED_EXECUTION_FILE_REQUIRED')
    # Current execution code was reviewed at the trusted master commit. The other
    # transition files must match both independently reviewed before/after blobs.
    remaining = [item for item in files if item.get('filename') != EXECUTION_FILE]
    P.verify_administration_files(remaining, {'files': REVIEWED_BOOTSTRAP_BLOBS})
    for name, entry in REVIEWED_BOOTSTRAP_BLOBS.items():
        previous = api.call('/repos/' + P.REPO + '/contents/' + urllib.parse.quote(name, safe='/') +
                            '?ref=' + source, missing=True)
        if entry['before_blob'] is None:
            P.require(previous is None, 'BOOTSTRAP_BEFORE_BLOB_MISMATCH')
        else:
            P.require(isinstance(previous, dict) and previous.get('type') == 'file' and
                      previous.get('sha') == entry['before_blob'], 'BOOTSTRAP_BEFORE_BLOB_MISMATCH')


def verify_plan_changed(api, event, commit):
    files = comparison_files(api, event.get('before'), commit)
    changes = [item for item in files if item['filename'] == 'release/approved-plan.json']
    P.require(len(changes) == 1 and changes[0].get('status') in ('added', 'modified') and
              'previous_filename' not in changes[0], 'PLAN_NOT_CHANGED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--validate-candidate', action='store_true')
    args = parser.parse_args()
    P.require(not (args.execute and args.validate_candidate), 'CANDIDATE_WRITE_FORBIDDEN')
    root = Path(__file__).resolve().parents[1]
    plan = json.loads((root / 'release/approved-plan.json').read_text())
    if plan.get('approved') is not True:
        if not args.validate_candidate and os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
                output.write('enabled=false\n')
        return
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    plan, commit = (candidate_context if args.validate_candidate else context)(os.environ, event, plan)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    P.require(head == commit, 'CHECKOUT_NOT_TRUSTED_MASTER')
    clean = subprocess.run(['git', 'diff', '--exit-code', 'HEAD', '--', 'scripts/release-admin.py', 'scripts/release-policy.py', 'scripts/license-gap-policy.py', 'scripts/maven-gap-policy.py', 'release/maven-license-gaps.json', 'release/approved-plan.json', '.github/workflows/release-admin.yml'], cwd=root, capture_output=True)
    P.require(clean.returncode == 0, 'TRUSTED_FILES_MODIFIED')
    api = GitHub()
    if not args.validate_candidate:
        verify_plan_changed(api, event, commit)
    admin = Admin(api, plan, commit)
    if args.validate_candidate:
        # Read-only branch validation never impersonates or mutates master.
        def fresh_candidate():
            value = api.call('/repos/' + P.REPO + '/git/ref/heads/feat/validation-release-packaging')
            P.require(value['object']['sha'] == commit, 'CANDIDATE_MOVED')
            master = P.sha(api.call('/repos/' + P.REPO + '/git/ref/heads/master')['object']['sha'])
            source = P.sha(plan.get('release_sha'))
            P.require(admin.ancestor(source, master) and admin.ancestor(master, commit),
                      'CANDIDATE_NOT_DESCENDANT_OF_RETAINED_MASTER')
        admin.fresh_master = fresh_candidate
    deadline = time.monotonic() + 120 * 60
    while True:
        try:
            runs = admin.validate()
            break
        except Pending:
            P.require(not args.execute and time.monotonic() < deadline, 'REQUIRED_WORKFLOW_NOT_TERMINAL')
            time.sleep(30)
    with tempfile.TemporaryDirectory(prefix='peerloom-verified-release-') as directory:
        outputs = admin.artifacts(Path(directory), runs)
        if args.execute:
            admin.publish(outputs)
    if not args.execute and not args.validate_candidate and os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write('enabled=true\n')

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Never print HTTP bodies, tokens, arbitrary plan values or subprocess stderr.
        print(str(error) if isinstance(error, P.Rejected) else 'RELEASE_ADMIN_FAILED_REQUIRES_REVIEW', file=sys.stderr)
        sys.exit(1)
