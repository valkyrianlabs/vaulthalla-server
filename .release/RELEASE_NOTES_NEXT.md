<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Clients and servers negotiate a protocol version

The server, the web console and Vaulthalla Desktop release on their own schedules, so a client now starts its
WebSocket session with `meta.hello` (on the web socket, once signed in: the server still tells no one its version
before login). It says which protocol versions it speaks; the server answers its product version,
the protocol version the session will use, the features it has (capabilities such as `fs.entry.metadata_version` or
`device.mcp`) and every command it offers. A client that has no version in common with the server gets a clear
`protocol_unsupported` answer naming the server's range instead of failing on a changed shape later. A paired device's
reported app version now stays current in the device list instead of keeping the version it paired with.

An unknown command now carries the error code `unknown_command` (the message is unchanged). The rules for what may
change within a protocol version are in [WebSocket Protocol](/reference/ws-protocol).
