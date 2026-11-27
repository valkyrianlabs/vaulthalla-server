"""Contract: every change to a mirrored vault's tree reaches its replication log (migration 160, design/peers/mirror.md).

The replication log of a vault this server is the core of is written by triggers on the tables that hold the vault's
replicated state, in the transaction of each mutation, so a write path can't skip it: FUSE seal, uploads, ws mutations,
copy, trash, purge, restore, sync, recovery, key rotation and psql by hand all reach those tables. This keeps that true:

  * migration 160 puts its triggers on fs_entry (update, delete), every table keyed by the entry (insert, delete;
    files and symlinks also update), files_trashed (insert, update, delete), the vault's settings (vault, sync, fsync,
    rsync, vault_recovery_policy) and vault_keys (insert, update);
  * every SQL writer of the entry tables (the journal contract's classification, which it shares) and of files_trashed
    in core/src is classified here with what it logs; a new one fails until it is, and
    core/tests/unit/test_replication_log.cpp (MirrorReplicationLogDbTest) drives each kind;
  * nothing bypasses row triggers on these tables, and nothing but db::query::mirror writes the log, the entry hashes
    or mirror_vault, or sets the transaction-local vh.mirror_apply switch that silences the triggers;
  * the canonical field list of the entry hash is the same in the migration and in core/include/mirror/Hash.hpp;
  * an HTTP upload's staging file (`.upload-http-*.part`, staged through the FUSE mount) is the one file that is not
    content: migration 166 leaves it out of the state documents, the tree and the trash (the four functions it
    replaces, one SQL rule), with the same rule as vh::fs::isUploadStagingName in C++, and its own upgrade test
    (SqlDeployerHistoryDb.MirrorPendingMigration166IsAdditiveAndIdempotent) proves the replacement.

Run by module: python3 -m unittest tools.contracts.test_replication_log_contract
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import unittest

from tools.contracts import test_fs_change_journal_contract as journal

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE = REPO_ROOT / "core"
PSQL = REPO_ROOT / "deploy" / "psql"
MIGRATION = PSQL / "160_replication_log.sql"
HASH_HEADER = CORE / "include" / "mirror" / "Hash.hpp"
DB_TEST = CORE / "tests" / "unit" / "test_replication_log.cpp"
MIRROR_QUERIES = ("core/src/db/query/mirror/", "core/include/db/query/mirror/")

SETTINGS_TABLES = ("vault", "sync", "fsync", "rsync", "vault_recovery_policy")
LOG_TABLES = ("vault_replication_log", "mirror_entry_hash", "mirror_vault")

TRASH_WRITE_RE = re.compile(r"\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+files_trashed\b")
LOG_WRITE_RE = re.compile(r"\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?)\s+(" + "|".join(LOG_TABLES)
                          + r")\b", re.IGNORECASE)
APPLY_SWITCH_RE = re.compile(r"vh\.mirror_(?:apply|local)")
GATE_MIGRATION = PSQL / "165_mirror_gate.sql"
GATE_TABLES = ("fs_entry", "files", "directories", "symlinks", "files_trashed")
BYPASS_RE = re.compile(r"session_replication_role|DISABLE\s+TRIGGER|TRUNCATE\s+(?:TABLE\s+)?(?:files_trashed|vault_keys"
                       r"|vault_replication_log|mirror_entry_hash)\b", re.IGNORECASE)

# Every SQL writer of files_trashed in core/src, per file, and what it logs on a core vault.
TRASH_WRITERS: dict[str, dict[str, int]] = {
    # mark_file_trashed(_by_id): the trash statement (with the entry's delete, folded into one `trash` row);
    # mark_trashed_file_deleted_by_*: `purge`.
    "core/src/db/preparedStatements/fs/files.cpp": {"INSERT INTO": 2, "UPDATE": 2},
    # markRemoteFileAsTrashed (the S3 gateway's delete of an object it never held as a file): `trash`.
    "core/src/db/query/fs/File.cpp": {"INSERT INTO": 1},
    # createTrashed (another writer's trashed file): `trash`.
    "core/src/db/query/sync/ManifestApply.cpp": {"INSERT INTO": 1},
    # The applier's restore (the trash row ends with the live file back under its uid): `restore`.
    "core/src/sync/vault_manifest/Applier.cpp": {"UPDATE": 1},
    # The mirror's log applier (db::query::mirror::ApplyRows): the core's trash rows (insert), their changes (update)
    # and their end (purge or restore: update). On the mirror only, under the apply switch: nothing logged.
    "core/src/db/query/mirror/Apply.cpp": {"INSERT INTO": 1, "UPDATE": 2},
    # `vh vault recover`: the restored vault's trash, written before it could be mirrored.
    "core/src/db/query/vault/Recover.cpp": {"INSERT INTO": 1},
}

# What each entry-table writer the journal contract classifies logs here (the journal's WRITERS keys must all be here,
# so a writer it learns about is classified for the log too).
ENTRY_WRITERS_LOG: dict[str, str] = {
    "core/src/db/preparedStatements/fs/directories.cpp": "upsert (a folder); ancestor totals and their mtime: nothing",
    "core/src/db/preparedStatements/fs/files.cpp": "upsert (create, content, a new seal, a key-version change); the "
                                                   "trash statement: trash",
    "core/src/db/preparedStatements/fs/fsEntries.cpp": "move (parent or name), upsert (attributes, mtime, attribution, "
                                                       "owner); delete_fs_entry*: delete",
    "core/src/db/preparedStatements/fs/symlinks.cpp": "upsert (a symlink)",
    "core/src/db/query/sync/ManifestApply.cpp": "upsert / move for another writer's entries, restore with the trash "
                                                "row's end",
    "core/src/db/query/vault/Recover.cpp": "nothing: the restored vault is new, and not mirrored",
    "core/src/db/query/mirror/Apply.cpp": "nothing: the mirror's applier writes under the apply switch, and a vault "
                                          "whose role here is mirror is never logged",
    "core/src/db/query/vault/Deletion.cpp": "nothing: the vault root, inodes, a soft-deleted vault",
    "core/src/db/query/mirror/Start.cpp": "nothing: the mirror's new vault and its root; never a core vault",
    "core/src/db/query/fs/Entry.cpp": "upsert (a setattr: mode, owner, group, modification time; ops::fs::setAttributes, "
                                      "with vh.actor)",
    "core/src/db/query/mirror/Copy.cpp": "upsert (detach a copy: the new local vault's entries take their source's mode "
                                         "and modification time, with vh.actor; never a held vault)",
}


def rel(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


def triggers(sql: str) -> dict[str, set[str]]:
    """table -> trigger events migration 160 creates on it (the DO block's tables included)."""
    out: dict[str, set[str]] = {}
    for match in re.finditer(r"CREATE TRIGGER \w+ (?:AFTER|BEFORE) ([A-Z ]+?) ON (\w+)", sql):
        out.setdefault(match.group(2), set()).update(e.strip() for e in match.group(1).split(" OR "))
    loop = re.search(r"FOREACH tbl IN ARRAY ARRAY\[([^\]]+)\]", sql)
    if loop:
        for table in re.findall(r"'(\w+)'", loop.group(1)):
            out.setdefault(table, set()).update({"INSERT", "UPDATE", "DELETE"})
    return out


def sources() -> list[Path]:
    return sorted(p for p in [*CORE.rglob("*.cpp"), *CORE.rglob("*.hpp")] if p.relative_to(CORE).parts[0] != "tests")


class ReplicationLogContractTests(unittest.TestCase):
    def test_every_replicated_table_is_logged(self) -> None:
        on = triggers(MIGRATION.read_text(encoding="utf-8"))
        self.assertEqual(on.get("fs_entry"), {"UPDATE", "DELETE"})
        typed = set()
        for path in sorted(PSQL.glob("*.sql")):
            typed.update(journal.TYPED_TABLE_RE.findall(path.read_text(encoding="utf-8")))
        self.assertEqual(typed, {"files", "directories", "symlinks"})
        for table in typed:
            self.assertTrue({"INSERT", "DELETE"} <= on.get(table, set()), f"{table}: creates and removals")
        for table in ("files", "symlinks"):
            self.assertIn("UPDATE", on.get(table, set()), f"{table}: content and target changes")
        self.assertEqual(on.get("files_trashed"), {"INSERT", "UPDATE", "DELETE"})
        for table in SETTINGS_TABLES:
            self.assertIn("UPDATE", on.get(table, set()), f"{table}: the vault's settings")
        self.assertEqual(on.get("vault_keys"), {"INSERT", "UPDATE"})

    def test_every_entry_writer_is_classified_for_the_log(self) -> None:
        self.assertEqual(set(journal.writers()), set(journal.WRITERS))
        self.assertEqual(set(ENTRY_WRITERS_LOG), set(journal.WRITERS),
                         "a writer of the entry tables the journal contract knows: say what it logs here")

    def test_every_trash_writer_is_classified(self) -> None:
        found: dict[str, Counter] = {}
        for path in sorted(p for p in (CORE / "src").rglob("*") if p.suffix in {".cpp", ".hpp"}):
            for match in TRASH_WRITE_RE.finditer(path.read_text(encoding="utf-8")):
                found.setdefault(rel(path), Counter())[re.sub(r"\s+", " ", match.group(1).upper())] += 1
        self.assertEqual(found, {path: Counter(c) for path, c in TRASH_WRITERS.items()},
                         "a new SQL writer of files_trashed: classify it in TRASH_WRITERS (what it logs) and cover it "
                         "in MirrorReplicationLogDbTest")

    def test_only_the_mirror_queries_write_the_log_or_silence_it(self) -> None:
        offenders = []
        for path in sources():
            r = rel(path)
            text = path.read_text(encoding="utf-8")
            if r.startswith(MIRROR_QUERIES):
                continue
            for match in LOG_WRITE_RE.finditer(text):
                offenders.append(f"{r}: {match.group(0)}")
            for match in APPLY_SWITCH_RE.finditer(text):
                offenders.append(f"{r}: {match.group(0)} (use db::query::mirror::Log::markMirrorApply / markMirrorLocal)")
        self.assertEqual(offenders, [])

    def test_the_backstop_guards_every_entry_table(self) -> None:
        """Migration 165: a held copy's entry tables refuse a change outside the follower's or a pending change's flag."""
        sql = GATE_MIGRATION.read_text(encoding="utf-8")
        on: dict[str, set[str]] = {}
        for match in re.finditer(r"CREATE TRIGGER vh_mirror_gate\w* BEFORE ([A-Z ]+?) ON (\w+)", sql):
            on.setdefault(match.group(2), set()).update(e.strip() for e in match.group(1).split(" OR "))
        self.assertEqual(set(on), set(GATE_TABLES))
        for table in GATE_TABLES:
            self.assertTrue({"INSERT", "DELETE"} <= on[table], f"{table}: creates and removals are refused")
        for table in ("fs_entry", "files", "symlinks", "files_trashed"):
            self.assertIn("UPDATE", on[table], f"{table}: a replicated change in place is refused")
        self.assertIn("vh.mirror_apply", sql)
        self.assertIn("vh.mirror_local", sql)

    def test_nothing_bypasses_the_triggers(self) -> None:
        offenders = []
        for path in [*sources(), *sorted(PSQL.glob("*.sql"))]:
            if rel(path) in journal.BYPASS_ALLOWED:
                continue
            for match in BYPASS_RE.finditer(path.read_text(encoding="utf-8")):
                offenders.append(f"{rel(path)}: {match.group(0)}")
        self.assertEqual(offenders, [])

    def test_the_hash_field_list_is_the_same_in_sql_and_cpp(self) -> None:
        sql = MIGRATION.read_text(encoding="utf-8")
        block = re.search(r"FUNCTION vh_mirror_state_hash\(.*?\$\$ LANGUAGE", sql, re.DOTALL)
        self.assertIsNotNone(block)
        calls = re.findall(r"vh_mirror_field\('([\w.]+)', state #>> '\{([\w,]+)\}'\)", block.group(0))
        for field, path in calls:
            self.assertEqual(field.split("."), path.split(","), f"{field}: the path must be the field's")
        sql_fields = [field for field, _ in calls]
        header = HASH_HEADER.read_text(encoding="utf-8")
        cpp = re.search(r"kEntryHashFields\{(.*?)\};", header, re.DOTALL)
        self.assertIsNotNone(cpp)
        self.assertEqual(re.findall(r'"([\w.]+)"', cpp.group(1)), sql_fields)
        self.assertIn(f"std::array<std::string_view, {len(sql_fields)}>", header)

    def test_an_upload_staging_file_is_left_out_with_one_rule(self) -> None:
        sql = (PSQL / "166_mirror_pending.sql").read_text(encoding="utf-8")
        rule = re.search(r"FUNCTION vh_mirror_upload_staging\(name TEXT\).*?\$\$(.*?)\$\$", sql, re.DOTALL)
        self.assertIsNotNone(rule)
        self.assertIn("starts_with(name, '.upload-http-')", rule.group(1))
        self.assertIn("right(name, 5) = '.part'", rule.group(1))
        cpp = (CORE / "src" / "fs" / "Filesystem.cpp").read_text(encoding="utf-8")
        self.assertIn('kHttpUploadTempPrefix = ".upload-http-"', cpp)
        self.assertRegex(cpp, r"isUploadStagingName\(const std::string_view name\) noexcept \{\s*return "
                              r"name\.starts_with\(kHttpUploadTempPrefix\) && name\.ends_with\(\"\.part\"\);")
        for name in ("vh_mirror_entry_state", "vh_mirror_tree_states", "vh_mirror_log_state", "vh_mirror_track_trash"):
            body = re.search(r"CREATE OR REPLACE FUNCTION " + name + r"\(.*?\n\$\$ LANGUAGE", sql, re.DOTALL)
            self.assertIsNotNone(body, f"166 replaces {name}")
            self.assertIn("vh_mirror_upload_staging(", body.group(0), f"{name} leaves staging files out")
        upgrade = (CORE / "tests" / "unit" / "test_sql_deployer_history.cpp").read_text(encoding="utf-8")
        self.assertIn("MirrorPendingMigration166IsAdditiveAndIdempotent", upgrade)
        self.assertIn("vh_mirror_upload_staging", upgrade)

    def test_the_db_suite_drives_each_path(self) -> None:
        text = DB_TEST.read_text(encoding="utf-8")
        for driver in ("fs::Filesystem::createFile", "engine->mkdir", "File::updateFile", "setEncryptionIVAndVersion",
                       "Symlink::upsertSymlink", "engine->rename", "engine->move", "engine->copy", "engine->remove",
                       "markTrashedFileDeleted", "UPDATE files_trashed SET deleted_at", "UPDATE fs_entry",
                       "DELETE FROM fs_entry", "prepare_key_rotation", "UPDATE vault SET", "markMirrorApply",
                       "s3Vault()", "Digests::recompute"):
            self.assertIn(driver, text, f"MirrorReplicationLogDbTest no longer drives {driver}")


if __name__ == "__main__":
    unittest.main()
