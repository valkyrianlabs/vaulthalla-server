## Linked servers (experimental, off by default)

- **Linked servers in the web console.** On a server with `peers.experimental: true`, super admins get a **Linked
  servers** page (System › Linked servers), marked Experimental, with what `vh peer` offers: the linked servers with
  each link's health (connected since when, which side dialled, round trip, the other server's version), how the
  link was checked, rename and unlink. **Accept a link** opens the window and shows this server's key and addresses,
  lists the servers that ask, and approves the one whose code you pick; **Link a server** dials another server by
  address and port, optionally pinned to its key, and shows the code to pick there. Making a link asks you to confirm
  it's you first. With the switch off (the default) the console shows no entry, and the page's address says only that
  linked servers aren't available on this server.
