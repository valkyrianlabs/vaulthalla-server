## Health

- The "Unauthenticated websocket sessions are active" warning is gone. It was raised by the desktop app's own
  signed-in device sessions, which were miscounted as unauthenticated, so a node showed a warning whenever the
  app was looking at it. Device sessions are now counted on their own, and sockets that have not signed in yet
  are only reported when 20 or more of them pile up; the ones that never sign in are still closed after the
  unauthenticated timeout.
