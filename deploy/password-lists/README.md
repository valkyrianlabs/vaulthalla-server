# Password-strength lists

The daemon reads these two files at startup (`<datadir>/vaulthalla/password-lists/`, i.e.
`/usr/share/vaulthalla/password-lists/` in the package) to refuse dictionary words and common passwords
(`core/src/crypto/password/Strength.cpp`, `auth/registration/Validator.cpp`). They ship with the package so that
nothing on the startup path touches the network: before #316 the daemon downloaded them from GitHub on every start,
and a host without outbound internet never started its ws/http listeners. Lists change only with a release.

| File | Entries | Source | License | SHA-256 |
|---|---|---|---|---|
| `common-passwords.txt` | 99,840 | SecLists `Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt` at commit `1a7bb9127eca9e6ff2fc0301c597fe6e16a0cb56` (the UK NCSC's top 100k passwords from the Have I Been Pwned corpus); CR stripped, otherwise byte for byte | MIT (SecLists, © 2018 Daniel Miessler) | `c2e5696882c603b76bb67a47ee970897e5a76fc4c3f5547abe3d0ca340c576e0` |
| `dictionary.txt` | 73,133 | SCOWL size 50 American English as packaged by Debian/Ubuntu `wamerican` 2020.12.07-2 (`/usr/share/dict/american-english`) | SCOWL (permissive; full statement in `SCOWL-COPYRIGHT`, installed alongside) | `8de59a93eca93b310d0d8bc260b0b6600158416560aa24bf1a1223986efc36da` |

The previous runtime dictionary (`dolph/dictionary` `popular.txt`) carries no license and can't be redistributed;
SCOWL size 50 covers 23,982 of its 25,322 words and more. The previous second password list (SecLists
`probable-v2_top-12000.txt`, CC BY-SA 4.0) added only 325 passwords long enough to pass the length rule and was dropped.

## Regenerating

```bash
# common-passwords.txt (pin a reviewed commit)
curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/<commit>/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt \
  | tr -d '\r' > common-passwords.txt

# dictionary.txt (on Ubuntu/Debian)
apt-get download wamerican && dpkg-deb -x wamerican_*.deb x
LC_ALL=C grep -E '^[A-Za-z]{3,}$' x/usr/share/dict/american-english | tr A-Z a-z | LC_ALL=C sort -u > dictionary.txt
cp x/usr/share/doc/wamerican/copyright SCOWL-COPYRIGHT
```

Update the table (commit, entries, SHA-256) and `debian/copyright` in the same change. The loader lowercases and
trims every line, ignores dictionary words shorter than three letters, and keeps the previous list if a file is
missing, empty or unreadable (logged at startup).
