## Linked servers (experimental, off by default)

- **Key rotation on a mirrored vault.** `vh vault keys rotate` now works on a vault's core while it is mirrored. Before
  anything is re-sealed, the core sends the new key version to the mirror the same way a start sends keys (wrapped
  to the mirror's peer key, proven there against the attestation key pinned at linking) and waits for its answer. If
  the mirror is not live, its link is down or it refuses the key, nothing is rotated, and the refusal says to try
  again once the link is up or to end the mirror first. The rotation then runs as on any vault. The mirror switches
  to the new version when the core's change log says so, and fetches the re-sealed files like any other change,
  without stopping. The old version stays on both servers, so files still sealed under it stay readable until their
  new bytes arrive. Key salvage on a mirrored vault is still refused, and so is a rotation on the mirror's side.
