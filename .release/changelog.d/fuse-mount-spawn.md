- The FUSE mount starts fusermount3 itself with posix_spawn (the same command and options libfuse runs) and hands
  libfuse the /dev/fuse descriptor it receives (/dev/fd/N), instead of libfuse's fork, whose child called setenv in a
  multithreaded process: under a sanitizer allocator that child could hang before exec, never mounting and keeping
  the daemon's listening sockets open. The helper no longer inherits any descriptor of the daemon but its socket.
  The gpg child of a key export no longer allocates between fork and exec.
