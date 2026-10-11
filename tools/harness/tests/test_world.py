"""Worlds: the pentest-v1 port, validation, seeded generation, fixture v1 emission, deterministic content."""
import argparse
import hashlib
import json
import unittest

from tests.helpers import pentest
from vhh import content, fixture_v1, oracle, worldgen
from vhh import world as W
from vhh._repo import pentest as P
from vhh._repo import REPO_ROOT, pentest_publish
from vhh.seeds import fmt_seed, h64


class PentestWorld(unittest.TestCase):
    def test_port_is_one_to_one(self):
        w = pentest()
        F = P.fixture
        self.assertEqual(w.validate(), [])
        self.assertEqual([p.id for p in w.principals], [u.opaque_id for u in F.USERS])
        self.assertEqual([v.id for v in w.vaults], [v.opaque_id for v in F.VAULTS])
        self.assertEqual(len(w.grants), len(F.VAULTS) + len(F.GRANTS))   # owner roles + declared grants
        self.assertEqual(len(w.objects), len(P.content.plan(None, REPO_ROOT)))
        self.assertFalse(w.principal("u-mallory").active)
        self.assertFalse(next(g for g in w.grants if g.subject == "u-bob" and g.vault == "v-team").active)

    def test_json_roundtrip_and_stable_hash(self):
        w = pentest()
        again = W.load(json.loads(json.dumps(w.to_json())))
        self.assertEqual(again.world_hash(), w.world_hash())
        self.assertEqual(W.pentest_v1().world_hash(), w.world_hash())
        w.grants[0].role = "reader"
        self.assertNotEqual(w.world_hash(), again.world_hash())

    def test_broken_world_lists_every_problem(self):
        d = pentest().to_json()
        d["grants"].append({"subject_kind": "user", "subject": "u-ghost", "vault": "v-nowhere", "role": "wizard"})
        d["overrides"][0]["pattern"] = "no-leading-slash/**"
        d["vaults"][0]["owner"] = "u-nobody"
        with self.assertRaises(W.WorldError) as cm:
            W.load(d)
        msg = str(cm.exception)
        for needle in ("u-ghost", "v-nowhere", "wizard", "vault-absolute", "u-nobody"):
            self.assertIn(needle, msg)
        with self.assertRaises(W.WorldError):
            W.load({"name": "x", "bogus_field": 1})
        with self.assertRaises(W.WorldError):
            W.load({"name": "empty"})          # no principals, no vaults

    def test_content_is_byte_exact_with_pentest_content(self):
        w = pentest()
        obj = next(o for o in w.objects if o.path == "/CANARY.txt" and o.vault == "v-alice")
        spec = next(s for s in P.content.plan(None, REPO_ROOT) if s.vault == "alice_private"
                    and s.path == "/CANARY.txt")
        self.assertEqual(content.object_bytes(w, obj), P.content.materialize(spec, None, REPO_ROOT))
        self.assertEqual(content.canaries_in(w, content.object_bytes(w, obj)), {"v-alice"})


class FixtureV1(unittest.TestCase):
    def test_manifest_matches_publish_py_for_pentest_v1(self):
        w = pentest()
        publish = pentest_publish()
        ids = {v.key: 100 + i for i, v in enumerate(w.vaults)}
        files = {}
        for o in w.objects:
            data = content.object_bytes(w, o)
            files[f"{w.vault(o.vault).key}:{o.path}"] = {"vault": w.vault(o.vault).key, "path": o.path,
                                                         "size": len(data), "tags": o.tags,
                                                         "sha256": hashlib.sha256(data).hexdigest()}
        shares = {s.key: {"opaque_id": s.id, "vault": next(v.key for v in w.vaults if v.id == s.vault),
                          "link_type": s.link_type, "allowed_ops": s.allowed_ops, "state": s.state}
                  for s in w.shares}
        state = {"vaults": {k: {"id": i} for k, i in ids.items()}, "files": files, "shares": shares,
                 "created_at": "2026-10-11T00:00:00Z"}
        ref = publish.build_manifest(state, argparse.Namespace(build_version="9.9.9", git_commit="abc"))
        mine = fixture_v1.manifest(w, build_version="9.9.9", git_commit="abc", built_at="2026-10-11T00:00:00Z",
                                   real_vault_ids=ids)
        ref.pop("generated_at")
        mine.pop("generated_at")
        self.assertEqual(mine, ref)
        self.assertEqual(fixture_v1.canaries(w), publish.build_canaries(state))

    def test_no_secret_in_published_dicts(self):
        w = pentest()
        blob = json.dumps(fixture_v1.manifest(w, build_version="1") | fixture_v1.canaries(w))
        for c in w.canaries.values():
            self.assertNotIn(c, blob)
        self.assertNotIn("password\":", blob)


class GeneratedWorlds(unittest.TestCase):
    def test_seeded_and_valid(self):
        for seed in (1, 2, 3, 0x5EED):
            for profile in worldgen.PROFILES:
                w = worldgen.generate(seed, profile)
                self.assertEqual(w.validate(), [], (seed, profile))
                self.assertEqual(worldgen.generate(seed, profile).world_hash(), w.world_hash())
        self.assertNotEqual(worldgen.generate(1).world_hash(), worldgen.generate(2).world_hash())
        self.assertEqual(worldgen.generate(7).seed, fmt_seed(7))

    def test_computed_expectations_and_unmapped(self):
        w = worldgen.generate(11, "pressure")
        m = fixture_v1.manifest(w, build_version="1")
        self.assertGreater(len(m["expectations"]), 0)
        self.assertIn("unmapped_probes", m["world"])
        for e in m["expectations"][:50]:
            self.assertEqual(oracle.decide_fixture(w, e["principal"], e["resource"], e["operation"],
                                                   e["path"]).expect, e["expect"])

    def test_seed_derivation_is_length_prefixed_blake2b(self):
        # reference vectors shared with the C++ side (Tier A must produce the same numbers)
        self.assertEqual(h64(), int.from_bytes(hashlib.blake2b(b"", digest_size=8).digest(), "little"))
        self.assertEqual(h64("ab"), int.from_bytes(hashlib.blake2b(b"\x02\x00\x00\x00ab",
                                                                   digest_size=8).digest(), "little"))
        self.assertNotEqual(h64("a", "b"), h64("ab"))


if __name__ == "__main__":
    unittest.main()
