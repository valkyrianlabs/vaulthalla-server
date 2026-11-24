- Stats: sessions of paired devices (SessionMode::Device, DevicePairing) are counted under their own modes in
  ConnectionStats::sessionsByMode, no longer as unauthenticated (every connected desktop app raised the
  connection-health warning). system.connections reports a finding only for 20 or more unauthenticated sessions;
  the "Unauthenticated websocket sessions are active" warning is gone.
