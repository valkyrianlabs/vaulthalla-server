- **The macOS package for 1.22 is available.** 1.22.1 shipped for Linux only, because the macOS installer's release
  check failed on virtual Macs. Those have no Secure Enclave, and since 1.22 the server refuses to keep secrets in
  plain files unless `secrets.allow_development_file_backend` is set (only the check was wrong; the server behaved as
  designed). This release publishes the 1.22 macOS package. It contains no other changes from 1.22.1.
