## Security

- **Automatic 1Password key backup is now a key-backup grant you can see, confirm and turn off.** A grant lets one
  paired Mac back up the keys of the vaults it names with no prompt, on every reconnect and after every key rotation.
  Any other key export from the Mac (another vault, a manual export) needs your approval each time: Touch ID on the
  Mac or your passkey in the web console.
- **Nothing stops when you upgrade.** Every Mac already paired keeps backing up: it gets a *migrated* grant over
  exactly the vaults its account could export at upgrade time, never more. **Devices › My devices** shows a Key backup
  column: confirm the grant or turn it off. A Mac you pair from now on asks once, when you turn backup on.
- **A new vault is added deliberately.** A grant never widens on its own; Desktop asks once to add a vault.
- **A Mac sweeping keys is stopped.** More than 60 vault key exports in an hour pauses the grant and notifies you;
  confirm it to resume.
- **Grants end automatically** when the Mac is unpaired, the account is deactivated, deleted or loses the export
  permission, its MFA is reset, someone signs in with a recovery code, or the Mac hasn't connected for 90 days. After
  a recovery-code sign-in, the same Mac can turn its backup back on with Touch ID during the cooldown, for the same
  vaults only.
- Every grant change and every backup under a grant is in the audit trail (`vh audit list --action keys.backup.`).
- The Desktop side (turning backup on per vault, the confirm prompt) ships in Vaulthalla Desktop.
