## Security

- **Master secrets stay in locked memory and are wiped when released.**
  - The daemon's sealed master secrets (vault master, API key and S3 gateway masters, the JWT master, the DB password, the key attestation seed and the device identity), the share-token pepper and unwrapped vault keys are now held in memory that is kept out of swap where the OS allows it and zeroed before it is freed.
  - Code that uses them borrows them in place instead of copying them into ordinary buffers. The short-lived copies other libraries insist on are wiped on every path, including when an operation fails partway.
  - The DB password is no longer kept as plain text in the connection settings between connects.
  - Nothing changes in how secrets are sealed or stored, and no operator action is needed.
