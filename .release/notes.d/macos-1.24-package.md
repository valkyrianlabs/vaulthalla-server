- **The macOS package for 1.24 is available.** 1.24.0 shipped for Linux only: its macOS installer failed to build,
  because one source file relied on another file in the same build group for a declaration it needed, and new files
  in 1.24 moved it to a group of its own. This release publishes the 1.24 macOS package. It contains no other changes
  from 1.24.0.
