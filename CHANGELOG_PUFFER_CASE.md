# Fix PUBG puffer_temp casing

- Canonicalize folder `Puffer_Temp` (and other case variants) to `puffer_temp` for PUBG auto and custom mapping.
- Preserve original PAK filenames and all other path segments.
- Apply the same normalization in Preview and Build via shared rule resolution.
- No changes to encryption, schema, or existing UI options.
- Verification: 11 unittest tests passed, including 4 new casing regression tests.
