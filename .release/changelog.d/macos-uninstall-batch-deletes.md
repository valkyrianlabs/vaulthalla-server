- macOS: uninstall.sh (also the cask's uninstall and zap step, so every Homebrew upgrade) removes the receipt's
  files and owned directories in xargs batches instead of one rm per path (~8,400 files and ~1,600 directories took
  ~25 s; now under a second), and announces the launchd wait only once a daemon is still loaded after 2 s.
