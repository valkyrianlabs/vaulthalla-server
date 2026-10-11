"""Connector for CLI-socket sessions, run as the actor's uid (started by the engine with subprocess user=/group=).

The daemon learns a CLI caller's identity from the peer credentials captured at connect(). This tiny process runs
with the actor's credentials, connects to the daemon's socket on request and passes the connected fd back to the
engine over the inherited control fd given as argv[2] (SCM_RIGHTS). The engine then speaks the frame protocol itself. One byte in = one connection out;
EOF on the control fd = exit. No threads, no daemon libraries.
"""
import socket
import sys


def main() -> int:
    path = sys.argv[1]
    ctl = socket.socket(fileno=int(sys.argv[2]))
    while True:
        b = ctl.recv(1)
        if not b:
            return 0
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(10)
        try:
            s.connect(path)
            socket.send_fds(ctl, [b"\x00"], [s.fileno()])
        except OSError as e:
            ctl.sendall(b"\x01" + str(e.errno or 0).encode()[:8])
        finally:
            s.close()


if __name__ == "__main__":
    sys.exit(main())
