- Test tooling: the Tier B harness and the lab ws clients (`vhws.py`, `parity_smoke.py`, `ws_churn.py`, the pentest
  fixture) sign admins in with a TOTP authenticator and answer step-up refusals with the password and a code, the
  same flow the console runs. Nothing in the daemon changed, and no test bypass was added (#395).
