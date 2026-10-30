# Per-file target editor and Terminal preview
- Added per-source/per-bundle destination overrides in Build and Preview.
- Added editable preview table with source, bundle, destination, terminal-style rule description, and size.
- Added validation for absolute/traversal/invalid destination paths and duplicate rule targets.
- Existing Auto/Custom Prefix behavior remains default when no overrides are specified.
- CLI build accepts --target-overrides JSON; no schema or encryption changes.
- Tests: 14 passed, 4 subtests passed; CLI Build and Verify smoke test passed.
- Flask HTTP/browser interaction not tested in this environment.
