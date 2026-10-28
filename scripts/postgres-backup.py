#!/usr/bin/env python3
"""受控本机 PostgreSQL 逻辑备份/新库恢复演练；不是生产恢复或 PITR 工具。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
MAX_ROWS = 100_000
MAX_OUTPUT = 16 * 1024 * 1024
MAX_ARCHIVE = 1024 * 1024 * 1024
NAME = re.compile(r"[a-zA-Z_][a-zA-Z_0-9]{0,62}\Z")
MIGRATION_LOCK = 0x504545524C4F4F4D
BUNDLE_FORMAT = "peerloom-local-logical-v2"


class Failure(Exception):
    pass


def require(value, code):
    if not value:
        raise Failure(code)


def private_file(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) & 0o077 == 0, "INSECURE_FILE")
    return info


def private_dir(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, "INSECURE_DIRECTORY")


def connection_env(source=None):
    source = os.environ if source is None else source
    require(not any(source.get(k) for k in ("PGPASSWORD", "PGSERVICE", "PGSERVICEFILE", "PGHOSTADDR")),
            "USE_EXPLICIT_LOCAL_PG_ENV_AND_PGPASSFILE")
    host = source.get("PGHOST", "")
    require(host in ("127.0.0.1", "::1") or (host.startswith("/") and "," not in host
            and "\n" not in host and Path(host).is_dir()), "LOCAL_PGHOST_REQUIRED")
    require(NAME.fullmatch(source.get("PGDATABASE", "")) and NAME.fullmatch(source.get("PGUSER", "")),
            "PLAIN_DATABASE_AND_USER_REQUIRED")
    port = source.get("PGPORT", "5432")
    require(port.isascii() and port.isdigit() and 1 <= int(port) <= 65535, "INVALID_PGPORT")
    env = {k: v for k, v in source.items() if not k.startswith("PG")}
    env.update(PGHOST=host, PGPORT=port, PGDATABASE=source["PGDATABASE"], PGUSER=source["PGUSER"],
               PGCONNECT_TIMEOUT="5", PGAPPNAME="peerloom-local-backup", PGSSLMODE="prefer",
               PGOPTIONS="-c statement_timeout=120000 -c lock_timeout=10000", LC_ALL="C")
    if source.get("PGPASSFILE"):
        private_file(Path(source["PGPASSFILE"]))
        env["PGPASSFILE"] = source["PGPASSFILE"]
    else:
        # Do not implicitly read a different ~/.pgpass. Socket/trust auth remains possible.
        env["PGPASSFILE"] = "/dev/null"
    return env


def run(args, env, output=None):
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_ARCHIVE, MAX_ARCHIVE))
    try:
        result = subprocess.run(args, env=env, stdin=subprocess.DEVNULL,
                                stdout=output if output is not None else subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=600, check=False,
                                preexec_fn=limits)
    except (OSError, subprocess.TimeoutExpired):
        raise Failure("POSTGRES_TOOL_UNAVAILABLE_OR_TIMEOUT") from None
    require(result.returncode == 0, "POSTGRES_TOOL_FAILED")
    return result.stdout


class SQL:
    """Keep the exported snapshot alive; never print libpq errors or supplied SQL."""
    def __init__(self, env):
        self.proc = subprocess.Popen(["psql", "-X", "-w", "-qAt", "-v", "ON_ERROR_STOP=1"],
                                     env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, bufsize=0)
        self.pending = b""

    def query(self, sql):
        marker = ("peerloom_end_" + uuid.uuid4().hex).encode()
        try:
            self.proc.stdin.write(sql.encode() + b"\n\\echo " + marker + b"\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            raise Failure("POSTGRES_SQL_FAILED") from None
        lines, size = [], 0
        deadline = time.monotonic() + 130
        with selectors.DefaultSelector() as selector:
            selector.register(self.proc.stdout, selectors.EVENT_READ)
            while True:
                while b"\n" in self.pending:
                    line, self.pending = self.pending.split(b"\n", 1)
                    if line == marker:
                        return b"\n".join(lines).decode("utf-8")
                    lines.append(line)
                    size += len(line) + 1
                    require(size <= MAX_OUTPUT, "EVIDENCE_OUTPUT_LIMIT")
                remaining = deadline - time.monotonic()
                require(remaining > 0 and selector.select(remaining), "POSTGRES_SQL_TIMEOUT")
                chunk = os.read(self.proc.stdout.fileno(), 65536)
                require(chunk, "POSTGRES_SQL_FAILED")
                self.pending += chunk
                require(size + len(self.pending) <= MAX_OUTPUT, "EVIDENCE_OUTPUT_LIMIT")

    def close(self):
        if self.proc.poll() is None:
            try:
                self.proc.stdin.write(b"ROLLBACK;\n\\q\n")
                self.proc.stdin.flush()
                self.proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                self.proc.kill()
                self.proc.wait()
        self.proc.stdin.close()
        self.proc.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def migrations(directory=ROOT / "infra/migrations"):
    result = []
    for path in sorted(directory.glob("*.up.sql")):
        stem = path.name.removesuffix(".up.sql")
        require(re.fullmatch(r"[0-9]{6}_[a-z0-9_]+", stem), "INVALID_MIGRATION_FILE")
        checksum = hashlib.sha256(path.read_bytes() + b"\0" + (directory / (stem + ".down.sql")).read_bytes()).hexdigest()
        result.append({"version": int(stem.split("_")[0]), "name": stem, "checksum": checksum})
    require(result and [v["version"] for v in result] == list(range(1, len(result) + 1)), "INVALID_MIGRATION_SEQUENCE")
    return result


def tools_major(env):
    versions = []
    for tool in ("psql", "pg_dump", "pg_restore"):
        text = run([tool, "--version"], env).decode("ascii")
        match = re.search(r"\(PostgreSQL\) (\d+)\.", text)
        require(match, "UNRECOGNIZED_POSTGRES_VERSION")
        versions.append(int(match[1]))
    require(len(set(versions)) == 1 and versions[0] >= 18, "MATCHING_PG18_OR_NEWER_TOOLS_REQUIRED")
    return versions[0]


def start_snapshot(db):
    db.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL TIME ZONE 'UTC'; "
             "SET LOCAL DateStyle='ISO, YMD'; SET LOCAL bytea_output='hex'; "
             "SET LOCAL search_path=pg_catalog,public;")
    db.query(f"SELECT pg_advisory_xact_lock_shared({MIGRATION_LOCK});")


SCHEMA_SQL = """
SELECT jsonb_build_object(
 'columns',(SELECT jsonb_agg(jsonb_build_array(c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),
 a.attnotnull,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid)) ORDER BY c.relname,a.attnum)
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
 WHERE n.nspname='public' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped),
 'constraints',(SELECT jsonb_agg(jsonb_build_array(c.relname,k.contype::text,k.conname,pg_get_constraintdef(k.oid),k.convalidated,k.conenforced)
 ORDER BY c.relname,k.conname) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
 JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'),
 'indexes',(SELECT jsonb_agg(jsonb_build_array(tablename,indexname,indexdef) ORDER BY tablename,indexname)
 FROM pg_indexes WHERE schemaname='public'),
 'extensions',(SELECT jsonb_agg(jsonb_build_array(extname,extversion) ORDER BY extname) FROM pg_extension),
 'functions',(SELECT jsonb_agg(jsonb_build_array(p.proname,pg_get_function_identity_arguments(p.oid),
 pg_get_functiondef(p.oid)) ORDER BY p.proname,pg_get_function_identity_arguments(p.oid))
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prokind<>'a'
 AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid='pg_proc'::regclass AND d.objid=p.oid
 AND d.refclassid='pg_extension'::regclass AND d.deptype='e')),
 'triggers',(SELECT jsonb_agg(jsonb_build_array(c.relname,t.tgname,pg_get_triggerdef(t.oid),t.tgenabled::text)
 ORDER BY c.relname,t.tgname) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
 JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal
 AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid='pg_trigger'::regclass AND d.objid=t.oid
 AND d.refclassid='pg_extension'::regclass AND d.deptype='e')))::text;
"""


def schema_digest(raw):
    document = json.loads(raw)
    require(isinstance(document, dict) and set(document) == {"columns", "constraints", "indexes", "extensions", "functions", "triggers"},
            "INVALID_SCHEMA_EVIDENCE")
    constraints = [] if document["constraints"] is None else document["constraints"]
    require(isinstance(constraints, list), "INVALID_CONSTRAINT_EVIDENCE")
    for key, limit in (("functions", 128), ("triggers", 256)):
        values = document[key]
        require(values is None or (isinstance(values, list) and len(values) <= limit), "SCHEMA_OBJECT_LIMIT")
    normalized = []
    for entry in constraints:
        require(isinstance(entry, list) and len(entry) == 6 and
                all(isinstance(entry[i], str) for i in range(4)) and
                entry[1] in ("c", "f", "n", "p", "u", "t", "x") and
                isinstance(entry[4], bool) and isinstance(entry[5], bool), "INVALID_CONSTRAINT_EVIDENCE")
        entry = entry.copy()
        if entry[1] == "n":
            # PG18 dump/restore may rename automatically generated NOT NULL constraints
            # copied with LIKE. Catalog has no auto-name flag: v2 deliberately excludes
            # n-type names only, never definitions, validation/enforcement or multiplicity.
            entry[2] = None
        normalized.append(entry)
    document["constraints"] = sorted(normalized, key=lambda entry: json.dumps(entry, ensure_ascii=True))
    return hashlib.sha256(json.dumps(document, ensure_ascii=True, sort_keys=True,
                                    separators=(",", ":")).encode()).hexdigest()


def sequence_evidence(db):
    # Sequences are not MVCC-snapshot state: backup also compares again after dump.
    value = db.query("SELECT coalesce(jsonb_agg(jsonb_build_array(sequencename,data_type::text,start_value,min_value,max_value,increment_by,cycle,cache_size,last_value) ORDER BY sequencename),'[]')::text FROM pg_sequences WHERE schemaname='public';")
    entries = json.loads(value)
    require(len(entries) <= 64 and all(NAME.fullmatch(entry[0]) for entry in entries), "UNSUPPORTED_SEQUENCE_SET")
    for entry in entries:
        state = json.loads(db.query(f'SELECT jsonb_build_array(last_value,is_called)::text FROM public."{entry[0]}";'))
        entry.append(state)
    return entries


def evidence(db, expected):
    unsupported = db.query("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' "
        "AND ((c.relkind IN ('r','p','f','S','m') AND n.nspname<>'public') OR c.relkind IN ('p','f','m')); ")
    require(unsupported == "0" and db.query("SELECT count(*) FROM pg_largeobject_metadata;") == "0", "UNSUPPORTED_DATABASE_OBJECTS")
    aggregates = db.query("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
        "WHERE n.nspname='public' AND p.prokind='a' AND NOT EXISTS (SELECT 1 FROM pg_depend d "
        "WHERE d.classid='pg_proc'::regclass AND d.objid=p.oid AND d.refclassid='pg_extension'::regclass AND d.deptype='e');")
    require(aggregates == "0", "UNSUPPORTED_USER_AGGREGATES")
    raw = db.query("SELECT coalesce(jsonb_agg(relname ORDER BY relname),'[]')::text FROM pg_class "
                   "WHERE relnamespace='public'::regnamespace AND relkind='r';")
    tables = json.loads(raw)
    require(0 < len(tables) <= 64 and all(NAME.fullmatch(t) for t in tables), "UNSUPPORTED_TABLE_SET")
    ledger = json.loads(db.query("SELECT coalesce(jsonb_agg(jsonb_build_object('version',version,'name',name,'checksum',checksum) "
                                "ORDER BY version),'[]')::text FROM public.schema_migrations;"))
    require(ledger == expected, "MIGRATION_LEDGER_MISMATCH")
    schema_hash = schema_digest(db.query(SCHEMA_SQL))
    remaining, result = MAX_ROWS, {}
    for table in tables:
        hashes = db.query(f'SELECT encode(sha256(convert_to(to_jsonb(t)::text,\'UTF8\')),\'hex\') '
                          f'FROM public."{table}" t ORDER BY 1 LIMIT {remaining + 1};').splitlines()
        require(len(hashes) <= remaining, "LOCAL_DRILL_ROW_LIMIT")
        require(all(re.fullmatch("[a-f0-9]{64}", h) for h in hashes), "INVALID_ROW_DIGEST")
        remaining -= len(hashes)
        result[table] = {"rows": len(hashes), "sha256": hashlib.sha256("".join(h + "\n" for h in hashes).encode()).hexdigest()}
    return {"migrations": ledger, "schema_sha256": schema_hash, "tables": result, "sequences": sequence_evidence(db)}


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def write_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def backup(directory, env):
    # A new directory is mandatory; existing directories/symlinks are never reused.
    directory.mkdir(mode=0o700)
    private_dir(directory)
    major, expected = tools_major(env), migrations()
    with SQL(env) as db:
        start_snapshot(db)
        version = int(db.query("SHOW server_version_num;"))
        require(version // 10000 == major, "SERVER_CLIENT_MAJOR_MISMATCH")
        require(db.query("SHOW server_encoding;") == "UTF8", "UTF8_DATABASE_REQUIRED")
        snapshot = db.query("SELECT pg_export_snapshot();")
        require(re.fullmatch("[A-Fa-f0-9-]+", snapshot), "INVALID_SNAPSHOT")
        facts = evidence(db, expected)
        archive = directory / "database.dump"
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            run(["pg_dump", "-w", "--format=custom", "--snapshot=" + snapshot,
                 "--lock-wait-timeout=10000", "--no-password"], env, output)
            output.flush()
            os.fsync(output.fileno())
        require(sequence_evidence(db) == facts["sequences"], "SEQUENCE_CHANGED_RETRY_WITH_QUIESCENT_SOURCE")
    size = private_file(archive).st_size
    require(0 < size <= MAX_ARCHIVE, "ARCHIVE_SIZE_LIMIT")
    metadata = {"format": BUNDLE_FORMAT, "created_at_unix": int(time.time()),
                "server_version_num": version, "tool_major": major,
                "archive_bytes": size, "archive_sha256": digest(archive), "evidence": facts,
                "scope": "single-database; not roles/secrets/PITR; restore drill omits owners/ACLs"}
    write_json(directory / "metadata.json", metadata)
    write_json(directory / "checksums.json", {"database.dump": metadata["archive_sha256"],
                                             "metadata.json": digest(directory / "metadata.json")})
    return {"status": "backup_created", "tables": len(facts["tables"]), "schema_version": expected[-1]["version"]}


def load_bundle(directory):
    private_dir(directory)
    for name in ("metadata.json", "checksums.json", "database.dump"):
        size = private_file(directory / name).st_size
        require(0 < size <= (MAX_ARCHIVE if name == "database.dump" else 1024 * 1024), "BUNDLE_SIZE_LIMIT")
    sums = json.loads((directory / "checksums.json").read_text())
    require(set(sums) == {"database.dump", "metadata.json"}, "INVALID_CHECKSUM_MANIFEST")
    require(all(digest(directory / name) == checksum for name, checksum in sums.items()), "CHECKSUM_MISMATCH")
    meta = json.loads((directory / "metadata.json").read_text())
    require(meta["format"] == BUNDLE_FORMAT and meta["archive_sha256"] == sums["database.dump"]
            and meta["archive_bytes"] == (directory / "database.dump").stat().st_size, "INVALID_METADATA")
    require(meta["evidence"]["migrations"] == migrations(), "MIGRATION_LEDGER_MISMATCH")
    return meta


def drill(directory, env, target=None, keep=False):
    meta = load_bundle(directory)
    major = tools_major(env)
    require(major == meta["tool_major"] == meta["server_version_num"] // 10000, "SERVER_CLIENT_MAJOR_MISMATCH")
    target = target or "peerloom_drill_" + uuid.uuid4().hex
    require(re.fullmatch(r"peerloom_drill_[a-z0-9_]{1,40}", target) and target != env["PGDATABASE"], "FRESH_DRILL_DATABASE_REQUIRED")
    admin_env = dict(env, PGDATABASE="postgres")
    print("本机隔离演练目标: " + target, file=sys.stderr)
    created, verified, cleaned, oid = False, False, False, None
    try:
        with SQL(admin_env) as admin:
            require(int(admin.query("SHOW server_version_num;")) // 10000 == major, "SERVER_CLIENT_MAJOR_MISMATCH")
            require(admin.query(f"SELECT count(*) FROM pg_database WHERE datname='{target}';") == "0", "TARGET_ALREADY_EXISTS")
            admin.query(f'CREATE DATABASE "{target}" TEMPLATE template0 ENCODING \'UTF8\';')
            created = True
            oid = admin.query(f"SELECT oid FROM pg_database WHERE datname='{target}';")
        restored_env = dict(env, PGDATABASE=target)
        run(["pg_restore", "-w", "--exit-on-error", "--single-transaction", "--no-owner", "--no-privileges",
             "--no-tablespaces", "--no-publications", "--no-subscriptions", "--dbname=" + target,
             str(directory / "database.dump")], restored_env)
        with SQL(restored_env) as restored:
            start_snapshot(restored)
            require(evidence(restored, migrations()) == meta["evidence"], "RESTORED_EVIDENCE_MISMATCH")
        verified = True
    finally:
        if created and not (verified and keep):
            with SQL(admin_env) as admin:
                require(admin.query(f"SELECT oid FROM pg_database WHERE datname='{target}';") == oid, "TARGET_OWNERSHIP_CHANGED")
                # No FORCE: never terminate other clients to make cleanup succeed.
                admin.query(f'DROP DATABASE "{target}";')
                cleaned = True
    report = {"status": "restore_evidence_verified", "schema_version": meta["evidence"]["migrations"][-1]["version"],
              "database": target, "target_removed": cleaned, "archive_sha256": meta["archive_sha256"],
              "evidence": meta["evidence"], "limits": "not application login/revocation/TLS/PITR/ACL acceptance"}
    write_json(directory / ("drill-" + uuid.uuid4().hex + ".json"), report)
    return {k: v for k, v in report.items() if k != "evidence"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("backup", "drill"))
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--local-operator", action="store_true", help="确认仅操作有权管理的本地数据库")
    parser.add_argument("--trust-local-archive", action="store_true", help="演练将执行归档内 SQL；确认来源可信")
    parser.add_argument("--target", help="仅允许不存在的 peerloom_drill_* 数据库；默认随机生成")
    parser.add_argument("--keep-target", action="store_true", help="仅成功后保留隔离数据库；默认删除")
    args = parser.parse_args(argv)
    try:
        require(args.local_operator, "EXPLICIT_LOCAL_OPERATOR_REQUIRED")
        require(args.command != "drill" or args.trust_local_archive, "TRUSTED_ARCHIVE_ACK_REQUIRED")
        require(args.command != "backup" or (not args.target and not args.keep_target), "INVALID_BACKUP_OPTIONS")
        env = connection_env()
        result = backup(args.directory, env) if args.command == "backup" else drill(args.directory, env, args.target, args.keep_target)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except Failure as err:
        print("本地备份/演练失败: " + str(err), file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # No repr/traceback: libpq exceptions and paths may contain private values.
        print("本地备份/演练失败: INVALID_INPUT_OR_LOCAL_TOOL_FAILURE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
