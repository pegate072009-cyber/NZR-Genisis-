NEZORA STORAGE FORMATTING FIX
File to update: src/storage.rs

These are the exact formatting corrections reported by GitHub Actions.

1) Around line 163

REPLACE:
ensure!(
    metadata.is_dir(),
    "inventory path must be a directory"
);

WITH:
ensure!(metadata.is_dir(), "inventory path must be a directory");


2) Around line 384

REPLACE:
let manifest_bytes = read_regular_file(
    &input_dir.join("manifest.json"),
    Some(MAX_MANIFEST_BYTES),
)?;

WITH:
let manifest_bytes =
    read_regular_file(&input_dir.join("manifest.json"), Some(MAX_MANIFEST_BYTES))?;


3) End of file

Make sure src/storage.rs ends with a single newline after the final closing brace.
Do not add another function or extra code.

AFTER APPLYING:
- Commit the change to src/storage.rs.
- Re-run the Nezora Rust CI workflow.

NOTE:
This fixes the rustfmt differences shown in CI. It does not by itself confirm that compilation or tests pass; check the next GitHub Actions run.
