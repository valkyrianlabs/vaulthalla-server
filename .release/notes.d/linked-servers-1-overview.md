## Linked servers and mirrored vaults

Two Vaulthalla servers can now be linked with each other, and a vault on one of them can be **mirrored** to the
other: one server stays the vault's **core**, the other holds a full, encrypted copy that follows every change, can
be worked in while the link is up, can take over when the core is gone, and can always be walked away with. It is
on with no setting to change, and a server that links nothing does nothing for it: no connection is made, no
background work runs, and the upgrade changes no existing vault, file or account.

**Try it** (as a super admin on both servers):

1. On the server that has the vault (the **core**), let the other server reach its device listener and open a
   10-minute pairing window:

   ```sh
   vh device remote enable
   vh peer pair
   ```

2. On the other server (the **mirror**), dial it. It prints a six-digit code:

   ```sh
   vh device remote enable
   vh peer link core.example.net        # host, or host:port (36972 by default)
   ```

3. Back on the core, `vh peer pair` shows three codes: pick the one the mirror printed (or approve later with
   `vh peer pending` and `vh peer approve <request> --code <code>`). A wrong pick declines the request. Both servers
   now list each other with `vh peer list`.
4. On the core, give the linked server a vault role: what its people may do in the vaults it mirrors from here
   (`reader` to only read, `contributor` to also change files):

   ```sh
   vh peer policy set <server> contributor
   ```

5. On the core, offer a vault (its number from `vh vault list`):

   ```sh
   vh mirror add <vault> --to <server>
   ```

6. On the mirror, accept the offer:

   ```sh
   vh mirror pending
   vh mirror accept <offer>
   ```

7. Watch it on either server: `vh mirror list` shows each mirrored vault, this server's role and its state, and
   `vh mirror info <vault>` shows one in detail, the first copy's progress included. Once the first copy has
   finished, the mirror's super admins work in the vault within the role you gave, and changes made on either server
   reach the other.

`<server>` is a linked server's number from `vh peer list`, its name or its node id. The web console has the same in
System › Linked servers (super admins only), with a Mirrored vaults tab.
