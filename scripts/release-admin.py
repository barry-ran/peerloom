#!/usr/bin/env python3
"""仅受审 master 计划可执行发布/精确租约清理；默认 preflight 只读。"""
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

class Pending(P.Rejected):
    pass

class GitHub:
    def call(self, endpoint, method='GET', data=None, missing=False):
        P.require(endpoint.startswith('/repos/' + P.REPO + '/'), 'API_SCOPE')
        command = ['gh', 'api', '--hostname', 'github.com', '--method', method, endpoint,
                   '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2022-11-28']
        if data is not None:
            command += ['--input', '-']
        result = subprocess.run(command, input=json.dumps(data) if data is not None else None,
                                text=True, capture_output=True, timeout=120)
        if missing and result.returncode and '(HTTP 404)' in result.stderr:
            return None
        P.require(result.returncode == 0, 'GITHUB_API_FAILED')
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

    def gates(self, commit, full):
        required = P.WORKFLOWS if full else {'ci.yml': P.WORKFLOWS['ci.yml']}
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
        P.require(plan.get('operation') in ('release', 'cleanup'), 'UNKNOWN_OPERATION')
        self.fresh_master()
        runs = self.gates(self.master, plan['operation'] == 'release')
        if plan['operation'] == 'cleanup':
            items = plan.get('branches')
            P.require(isinstance(items, list) and 0 < len(items) <= len(P.TASK_BRANCHES), 'CLEANUP_PLAN_REQUIRED')
            P.require(len({i.get('branch') for i in items}) == len(items), 'DUPLICATE_BRANCH')
            for item in items:
                P.validate_cleanup(item, self.master,
                    lambda commit: self.api.call(self.base + '/git/commits/' + commit), self.ancestor)
            return runs
        release_sha = P.sha(plan.get('release_sha'))
        P.require(release_sha != self.master and self.ancestor(release_sha, self.master), 'RELEASE_NOT_PREVIOUS_RETAINED_COMMIT')
        P.require(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', plan.get('tag', '')), 'VERSION_TAG_REQUIRED')
        P.require(type(plan.get('prerelease')) is bool and isinstance(plan.get('notes'), str) and 0 < len(plan['notes']) <= 65536, 'RELEASE_DESCRIPTION_REQUIRED')
        P.require(plan.get('final_scope_accepted') is True, 'FINAL_SCOPE_NOT_ACCEPTED')
        P.require(set(plan.get('artifacts', {})) == set(P.PLATFORMS), 'ALL_PLATFORM_ARTIFACTS_REQUIRED')
        return self.gates(release_sha, True)

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
            output = directory / f"peerloom-{self.plan['tag']}-{platform}.zip"
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

    def cleanup(self, execute):
        for item in self.plan['branches']:
            self.fresh_master()
            branch, expected = P.validate_cleanup(item, self.master,
                lambda commit: self.api.call(self.base + '/git/commits/' + commit), self.ancestor)
            ref = self.api.call(self.base + '/git/ref/heads/' + branch, missing=True)
            if ref is None:
                continue
            P.require(ref['object']['sha'] == expected, 'BRANCH_MOVED')
            execute(P.deletion_command(branch, expected))
            P.require(self.api.call(self.base + '/git/ref/heads/' + branch, missing=True) is None, 'BRANCH_DELETE_NOT_CONFIRMED')

def context(env, event, plan):
    P.require(env.get('GITHUB_EVENT_NAME') == 'push' and env.get('GITHUB_REPOSITORY') == P.REPO and
              env.get('GITHUB_REF') == 'refs/heads/master' and event.get('repository', {}).get('full_name') == P.REPO and
              event.get('ref') == 'refs/heads/master' and event.get('after') == env.get('GITHUB_SHA') and
              not event.get('created') and not event.get('deleted') and not event.get('forced'), 'UNTRUSTED_EVENT')
    commit = P.sha(env.get('GITHUB_SHA'))
    before = P.sha(event.get('before'))
    P.require(before != '0' * 40 and before != commit, 'PUSH_RANGE_REQUIRED')
    P.require(plan.get('administration_sha') == 'event', 'PLAN_EVENT_BINDING_REQUIRED')
    plan = dict(plan, administration_sha=commit)
    return plan, commit

def verify_plan_changed(api, event, commit):
    # Actions deliberately omits added/removed/modified from commit payloads.
    # Compare only the already-validated immutable before/after SHAs, not a URL
    # supplied by the event. GitHub caps comparison files at 300: fail closed at
    # that boundary rather than pretend the returned inventory is complete.
    before = P.sha(event.get('before'))
    commit = P.sha(commit)
    P.require(before != '0' * 40 and before != commit, 'PUSH_RANGE_REQUIRED')
    value = api.call('/repos/' + P.REPO + '/compare/' + before + '...' + commit + '?per_page=100&page=1')
    P.require(value.get('base_commit', {}).get('sha') == before and
              value.get('merge_base_commit', {}).get('sha') == before and
              value.get('status') == 'ahead' and value.get('behind_by') == 0 and
              type(value.get('ahead_by')) is int and value['ahead_by'] > 0 and
              value.get('total_commits') == value['ahead_by'], 'PUSH_NOT_FAST_FORWARD')
    files = value.get('files')
    P.require(isinstance(files, list) and 0 < len(files) < 300, 'COMPARE_FILE_LIST_UNPROVEN')
    names = [item.get('filename') for item in files]
    P.require(all(isinstance(name, str) for name in names) and len(names) == len(set(names)), 'COMPARE_FILE_LIST_INVALID')
    changes = [item for item in files if item['filename'] == 'release/approved-plan.json']
    P.require(len(changes) == 1 and changes[0].get('status') in ('added', 'modified') and
              'previous_filename' not in changes[0], 'PLAN_NOT_CHANGED')


def execute_delete(command):
    with tempfile.TemporaryDirectory(prefix='peerloom-release-auth-') as directory:
        helper = Path(directory) / 'askpass.py'
        helper.write_text('#!/usr/bin/env python3\nimport os,sys\nprint("x-access-token" if "Username" in sys.argv[1] else os.environ["GH_TOKEN"])\n')
        helper.chmod(0o700)
        env = dict(os.environ, GIT_ASKPASS=str(helper), GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
        result = subprocess.run(command, env=env, capture_output=True, timeout=120)
        P.require(result.returncode == 0, 'EXACT_LEASE_DELETE_FAILED_NO_RETRY')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    plan = json.loads((root / 'release/approved-plan.json').read_text())
    if plan.get('approved') is not True:
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
                output.write('enabled=false\n')
        return
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    plan, commit = context(os.environ, event, plan)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    P.require(head == commit, 'CHECKOUT_NOT_TRUSTED_MASTER')
    clean = subprocess.run(['git', 'diff', '--exit-code', 'HEAD', '--', 'scripts/release-admin.py', 'scripts/release-policy.py', 'scripts/license-gap-policy.py', 'release/approved-plan.json', '.github/workflows/release-admin.yml'], cwd=root, capture_output=True)
    P.require(clean.returncode == 0, 'TRUSTED_FILES_MODIFIED')
    api = GitHub()
    verify_plan_changed(api, event, commit)
    admin = Admin(api, plan, commit)
    deadline = time.monotonic() + 90 * 60
    while True:
        try:
            runs = admin.validate()
            break
        except Pending:
            P.require(not args.execute and time.monotonic() < deadline, 'REQUIRED_WORKFLOW_NOT_TERMINAL')
            time.sleep(30)
    with tempfile.TemporaryDirectory(prefix='peerloom-verified-release-') as directory:
        outputs = admin.artifacts(Path(directory), runs) if plan['operation'] == 'release' else None
        if args.execute:
            if outputs is not None:
                admin.publish(outputs)
            else:
                admin.cleanup(execute_delete)
    if not args.execute and os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write('enabled=true\n')

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Never print HTTP bodies, tokens, arbitrary plan values or subprocess stderr.
        print(str(error) if isinstance(error, P.Rejected) else 'RELEASE_ADMIN_FAILED_REQUIRES_REVIEW', file=sys.stderr)
        sys.exit(1)
