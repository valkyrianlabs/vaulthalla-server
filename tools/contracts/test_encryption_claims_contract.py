"""Contract: product text makes only the encryption claims spec 05 §6 allows (#364, WS5-a).

The lint itself is `tools/contracts/encryption_claims.py`. These tests pin its rules with allowed and disallowed
samples, prove that a seeded violation fails, and keep `docs/`, `README.md` and `web/src` clean.
"""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
import tempfile
import unittest

from tools.contracts import encryption_claims as claims

REPO_ROOT = Path(__file__).resolve().parents[2]
PATH_V0 = "File contents are encrypted before upload. File and folder names are visible to your storage provider."


def rule_ids(text: str, *, prose: bool = True) -> list[str]:
    return [finding.rule_id for finding in claims.check_text(text, prose=prose)]


class DisallowedPhraseTests(unittest.TestCase):
    """Each sample is product text spec 05 §6 forbids; the lint must name the rule."""

    DISALLOWED = {
        "Military-grade encryption for every file.": "superlative",
        "An unbreakable vault.": "superlative",
        "Unhackable by design.": "superlative",
        "Bank-level security for your files.": "superlative",
        "Vaulthalla is zero-knowledge storage.": "zero-knowledge",
        "Zero knowledge: we never see your data.": "zero-knowledge",
        "Server vaults are end-to-end encrypted.": "end-to-end",
        "Your files are end to end encrypted.": "end-to-end",
        "Vaulthalla supports E2EE for S3 vaults.": "end-to-end",
        "Encrypted vaults are provider-blind.": "blindness",
        "Self-hosting makes the vault operator-blind to Valkyrian Labs.": "blindness",
        "The bucket only ever sees ciphertext.": "provider-sees-nothing",
        "Your provider knows nothing about your files.": "provider-sees-nothing",
        "Nobody can read your data.": "nobody-can-read",
        "We can't access your data.": "nobody-can-read",
        "Valkyrian Labs cannot read your files.": "nobody-can-read",
        "Only you can decrypt your vault.": "nobody-can-read",
        "Encrypted storage on local disk or S3.": "encrypted-storage",
        "Vaulthalla is HIPAA compliant.": "compliance",
        "A SOC 2 certified storage server.": "compliance",
        "The server is compliant with GDPR.": "compliance",
        "Restore any vault from the bucket alone.": "bucket-only-recovery",
        "You can recover a vault from your bucket only, with nothing else.": "bucket-only-recovery",
        "Valkyrian Labs can recover your data if you lose your keys.": "vl-recovers",
        "We can restore your keys.": "vl-recovers",
        "Recovery requires a subscription.": "vl-recovers",
        "Vaulthalla Cloud Assisted Recovery is available today.": "cloud-recovery",
        "Custodial recovery is included with managed storage.": "cloud-recovery",
        "Sign up at vaulthalla.cloud for key escrow.": "cloud-recovery",
        "Your account includes custody of your keys.": "custody-tie",
        "Subscribing to managed B2 enrolls you in key recovery.": "custody-tie",
    }

    def test_every_disallowed_sample_fails_with_its_rule(self) -> None:
        for text, rule in self.DISALLOWED.items():
            with self.subTest(text=text):
                self.assertIn(rule, rule_ids(text))

    def test_console_strings_are_checked_line_by_line(self) -> None:
        source = "const hint = 'The bucket only ever sees ciphertext. Recommended.'\n"
        self.assertEqual(rule_ids(source, prose=False), ["provider-sees-nothing"])

    def test_curly_apostrophes_and_emphasis_do_not_hide_a_claim(self) -> None:
        self.assertIn("nobody-can-read", rule_ids("We can’t access your data."))
        self.assertIn("end-to-end", rule_ids("Files are **end-to-end encrypted**."))

    def test_a_claim_wrapped_across_lines_is_still_found(self) -> None:
        findings = claims.check_text("Intro line.\nYour vaults are end-to-end\nencrypted, always.\n", "x.md")
        self.assertEqual([(f.rule_id, f.line) for f in findings], [("end-to-end", 2)])


class AllowedWordingTests(unittest.TestCase):
    """The sentences spec 05 §6 approves, and ordinary uses of the same words, pass."""

    ALLOWED = (
        # §6 `path_v0`, today's wording for every upstream-encrypted vault.
        PATH_V0,
        "Sovereign, encrypted storage on hardware you own. " + PATH_V0,
        # §6 `opaque_v1`.
        "Your storage provider only ever sees encrypted, opaquely named objects. It can't see your file names, folders "
        "or contents. It can see how many objects you store, their sizes and when they change.",
        # §6 sealed vaults and the only allowed "zero-knowledge".
        "End-to-end encrypted: files and names are encrypted on your devices. In a sealed vault the server and storage "
        "hold only ciphertext and wrapped keys, so neither we nor your provider can read them.",
        "Sealed vaults are zero-knowledge. The server still sees file sizes, counts and activity times.",
        # Negations and qualifiers.
        "`path_v0` vaults are not provider-blind: names are visible to the provider.",
        "Restoring a vault from its encrypted files alone, after the database is lost, is not possible.",
        "A vault can't be restored from its bucket alone.",
        "Vaulthalla Cloud Assisted Recovery is planned and not implemented.",
        "Custodial recovery is planned; it isn't available.",
        "Do not escrow content-decryption material to Valkyrian Labs.",
        "Vaulthalla doesn't make an operator HIPAA compliant.",
        "Designed to support the technical safeguards in HIPAA; see the audit trail page.",
        "Never leave encrypted storage permanently inaccessible.",
        # Same words, no encryption claim.
        "Anonymous share links are disabled.",
        "A metadata-free object over an encrypted file is treated as foreign.",
        "Desktop's client certificate and the node's pinned key travel end to end.",
        "The daemon only ever sees the vault path.",
        "The default of six years matches the HIPAA documentation retention period.",
        "Restore the file from a backup.",
        "Assign the key_custodian role.",
    )

    def test_every_allowed_sample_passes(self) -> None:
        for text in self.ALLOWED:
            with self.subTest(text=text):
                self.assertEqual(claims.check_text(text), [])

    def test_a_qualifier_in_another_paragraph_does_not_count(self) -> None:
        text = "Sealed vaults are planned.\n\nYour files are end-to-end encrypted.\n"
        self.assertEqual(rule_ids(text), ["end-to-end"])

    def test_a_negation_or_planned_in_another_sentence_does_not_count(self) -> None:
        self.assertEqual(
            rule_ids("Vaulthalla Cloud Assisted Recovery is available today. Sealed vaults are planned."),
            ["cloud-recovery"],
        )
        self.assertEqual(rule_ids("Valkyrian Labs can recover your data. No account needed."), ["vl-recovers"])
        self.assertEqual(rule_ids("Never lose a file. Vaults are provider-blind."), ["blindness"])

    def test_sealed_overclaims_apply_only_in_sealed_context(self) -> None:
        self.assertEqual(rule_ids("Anonymous links are enabled."), [])
        self.assertIn("sealed-overclaim", rule_ids("Sealed vaults are anonymous and metadata-free."))


class SeededViolationTests(unittest.TestCase):
    def test_a_seeded_violation_in_a_scanned_tree_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vh-claims-") as tmp:
            root = Path(tmp)
            (root / "docs/vaults").mkdir(parents=True)
            (root / "web/src/features").mkdir(parents=True)
            (root / "docs/vaults/encryption.md").write_text(f"# Encryption\n\n{PATH_V0}\n", encoding="utf-8")
            (root / "README.md").write_text("Vaulthalla.\n", encoding="utf-8")
            (root / "web/src/features/Page.tsx").write_text("const t = 'Copy.'\n", encoding="utf-8")
            self.assertEqual(claims.check_repo(root), [])

            (root / "web/src/features/Page.tsx").write_text("const t = 'Zero-knowledge vaults.'\n", encoding="utf-8")
            (root / "docs/vaults/encryption.md").write_text("Military-grade, end-to-end encrypted.\n", encoding="utf-8")
            found = sorted((f.path, f.rule_id) for f in claims.check_repo(root))
            self.assertEqual(
                found,
                [
                    ("docs/vaults/encryption.md", "end-to-end"),
                    ("docs/vaults/encryption.md", "superlative"),
                    ("web/src/features/Page.tsx", "zero-knowledge"),
                ],
            )
            report = io.StringIO()
            with contextlib.redirect_stdout(report):
                self.assertEqual(claims.main([str(root / "docs/vaults/encryption.md")]), 1)
            self.assertIn("[superlative] 'Military-grade'", report.getvalue())


class RepositoryClaimsTests(unittest.TestCase):
    def test_scan_covers_docs_readme_and_console(self) -> None:
        scanned = {str(path.relative_to(REPO_ROOT)) for path in claims.iter_product_files()}
        for expected in (
            "README.md",
            "docs/stack.toml",
            "docs/vaults/encryption.md",
            "web/src/features/vaults/NewVaultPage.tsx",
            "web/src/features/vaults/encryptionCopy.ts",
        ):
            self.assertIn(expected, scanned)
        self.assertFalse(any("node_modules" in path for path in scanned))

    def test_product_text_makes_no_disallowed_claim(self) -> None:
        findings = claims.check_repo()
        self.assertEqual(findings, [], "\n" + "\n".join(str(finding) for finding in findings))

    def test_docs_and_console_use_the_path_v0_sentence(self) -> None:
        doc = (REPO_ROOT / "docs/vaults/encryption.md").read_text(encoding="utf-8")
        self.assertIn(PATH_V0, doc)
        copy = (REPO_ROOT / "web/src/features/vaults/encryptionCopy.ts").read_text(encoding="utf-8")
        self.assertIn(PATH_V0, " ".join(line.strip().strip("'") for line in copy.splitlines()))
        for page in ("web/src/features/vaults/NewVaultPage.tsx", "web/src/features/vaults/settings/VaultSettings.tsx",
                     "web/src/features/gateway/BucketDialogs.tsx"):
            with self.subTest(page=page):
                self.assertIn("UPSTREAM_ENCRYPTION_ON", (REPO_ROOT / page).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
