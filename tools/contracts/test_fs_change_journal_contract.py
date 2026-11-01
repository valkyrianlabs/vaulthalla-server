"""Contract: every write to a filesystem entry is journaled (#259, migration 115, fs.changes.list).

The change journal is written by triggers on the entry tables, in the transaction of each mutation, so a write path
can't forget to journal: FUSE seal, uploads, ws mutations, copy, trash, sync, recovery and psql by hand all reach
fs_entry / files / directories / symlinks. This keeps that true:

  * migration 115 puts its triggers on fs_entry (update, delete) and on every table keyed by the entry (a table whose
    primary key is `fs_entry_id ... REFERENCES fs_entry`: the entry's type and content; create, update);
  * nothing in core or the migrations bypasses row triggers (session_replication_role, DISABLE TRIGGER, TRUNCATE of
    an entry table), except the test-only schema wipe;
  * folder and symlink type rows go only through their entry's cascade (the delete trigger reads the type from them
    before it runs), and only the trash statement removes a files row first;
  * every SQL writer of the entry tables in core/src is classified below. A new one fails here until it is added
    with what it journals; core/tests/unit/test_fs_change_journal.cpp (FsChangeJournalDbTest) drives each kind.

Run by module: python3 -m unittest tools.contracts.test_fs_change_journal_contract
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE = REPO_ROOT / "core"
PSQL = REPO_ROOT / "deploy" / "psql"
MIGRATION = PSQL / "115_fs_change_log.sql"
DB_TEST = CORE / "tests" / "unit" / "test_fs_change_journal.cpp"

ENTRY_TABLES = ("fs_entry", "files", "directories", "symlinks")
WRITE_RE = re.compile(r"\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(" + "|".join(ENTRY_TABLES) + r")\b")

# Every SQL writer of the entry tables in core/src, per file: (statement, table) -> count, and what each journals.
WRITERS: dict[str, dict[tuple[str, str], int]] = {
    # upsert_directory: create (directories insert); upserts of an existing one: nothing. Ancestor totals and
    # updated_at (update_dir_stats, add_to_ancestor_dir_stats): nothing.
    "core/src/db/preparedStatements/fs/directories.cpp": {
        ("UPDATE", "directories"): 2, ("UPDATE", "fs_entry"): 2, ("INSERT INTO", "fs_entry"): 1,
        ("INSERT INTO", "directories"): 1,
    },
    # upsert_file_full / upsert_file_by_entry_id: create (files insert) or update (content); update_file_only (the
    # FUSE seal and overwrite): update; set/compare_and_set IV and version: update for a new seal, nothing for key
    # rotation; mark_file_trashed(_by_id): delete.
    "core/src/db/preparedStatements/fs/files.cpp": {
        ("INSERT INTO", "files"): 2, ("UPDATE", "fs_entry"): 1, ("UPDATE", "files"): 3, ("INSERT INTO", "fs_entry"): 1,
        ("DELETE FROM", "files"): 2, ("DELETE FROM", "fs_entry"): 2,
    },
    # update_fs_entry_by_inode / rename_fs_entry: move, rename or update; delete_fs_entry*: delete.
    "core/src/db/preparedStatements/fs/fsEntries.cpp": {("UPDATE", "fs_entry"): 2, ("DELETE FROM", "fs_entry"): 3},
    # insert_symlink_full: create (symlinks insert).
    "core/src/db/preparedStatements/fs/symlinks.cpp": {("INSERT INTO", "fs_entry"): 1, ("INSERT INTO", "symlinks"): 1},
    # Vault deletion/revival re-parents the vault root and clears inodes: the root is never journaled, inodes aren't
    # changes, and a purge's cascade skips a deleted vault.
    "core/src/db/query/vault/Deletion.cpp": {("UPDATE", "fs_entry"): 3},
}

BYPASS_RE = re.compile(r"session_replication_role|DISABLE\s+TRIGGER|TRUNCATE\s+(?:TABLE\s+)?(?:"
                       + "|".join(ENTRY_TABLES) + r")\b", re.IGNORECASE)
# The test-only schema wipe (refuses outside test mode and off vh_harness_*/ *test* databases).
BYPASS_ALLOWED = {"core/seed/include/init_db_tables.hpp"}

TYPED_TABLE_RE = re.compile(r"CREATE TABLE IF NOT EXISTS (\w+)\s*\(\s*fs_entry_id\s+INTEGER\s+PRIMARY KEY\s+"
                            r"REFERENCES\s+fs_entry\s*\(id\)", re.IGNORECASE)


def rel(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


def code_sources() -> list[Path]:
    return sorted(p for p in (CORE / "src").rglob("*") if p.suffix in {".cpp", ".hpp"})


def writers() -> dict[str, Counter]:
    found: dict[str, Counter] = {}
    for path in code_sources():
        text = path.read_text(encoding="utf-8")
        for match in WRITE_RE.finditer(text):
            verb = re.sub(r"\s+", " ", match.group(1).upper())
            found.setdefault(rel(path), Counter())[(verb, match.group(2))] += 1
    return found


def triggers(sql: str) -> dict[str, set[str]]:
    """table -> trigger events (INSERT/UPDATE/DELETE) migration 115 creates directly on it."""
    out: dict[str, set[str]] = {}
    for match in re.finditer(r"CREATE TRIGGER \w+ (?:AFTER|BEFORE) ([A-Z ]+?) ON (\w+)", sql):
        out.setdefault(match.group(2), set()).update(e.strip() for e in match.group(1).split(" OR "))
    return out


class FsChangeJournalContractTests(unittest.TestCase):
    def test_every_entry_table_is_journaled(self) -> None:
        sql = MIGRATION.read_text(encoding="utf-8")
        typed = set()
        for path in sorted(PSQL.glob("*.sql")):
            typed.update(TYPED_TABLE_RE.findall(path.read_text(encoding="utf-8")))
        self.assertEqual(typed, {"files", "directories", "symlinks"},
                         "a new table keyed by the entry is part of its state: journal it in a new migration and "
                         "classify it here")
        on = triggers(sql)
        self.assertEqual(on.get("fs_entry"), {"UPDATE", "DELETE"})
        for table in typed:
            self.assertIn("INSERT", on.get(table, set()), f"{table}: a new row is the entry's create")
        for table in ("files", "symlinks"):
            self.assertIn("UPDATE", on.get(table, set()), f"{table}: its content changes are updates")

    def test_every_writer_is_classified(self) -> None:
        found = writers()
        expected = {path: Counter(counts) for path, counts in WRITERS.items()}
        self.assertEqual(found, expected,
                         "a new SQL writer of fs_entry/files/directories/symlinks: classify it in WRITERS (what it "
                         "journals) and cover it in FsChangeJournalDbTest")

    def test_type_rows_leave_only_through_their_entry(self) -> None:
        for path, counts in writers().items():
            for table in ("directories", "symlinks"):
                self.assertEqual(counts[("DELETE FROM", table)], 0, f"{path} deletes a {table} row directly")

    def test_nothing_bypasses_row_triggers(self) -> None:
        offenders = []
        sources = [p for p in [*CORE.rglob("*.cpp"), *CORE.rglob("*.hpp")] if p.relative_to(CORE).parts[0] != "tests"]
        for path in [*sorted(sources), *sorted(PSQL.glob("*.sql"))]:
            if rel(path) in BYPASS_ALLOWED:
                continue
            for match in BYPASS_RE.finditer(path.read_text(encoding="utf-8")):
                offenders.append(f"{rel(path)}: {match.group(0)}")
        self.assertEqual(offenders, [])

    def test_the_db_suite_drives_each_path(self) -> None:
        text = DB_TEST.read_text(encoding="utf-8")
        for driver in ("Filesystem::createFile", "engine->mkdir", "File::updateFile", "setEncryptionIVAndVersion",
                       "Symlink::upsertSymlink", '"rename"', '"move"', '"copy"', '"delete"', "UPDATE fs_entry"):
            self.assertIn(driver, text, f"FsChangeJournalDbTest no longer drives {driver}")


if __name__ == "__main__":
    unittest.main()
