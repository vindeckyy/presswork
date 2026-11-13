## Summary

<!-- what changed and why; link the issue if one exists -->

## Compatibility impact

<!-- does this change any behavior observable by a CUPS client,
config file, filter, or backend? if so, which upstream semantics
does it match (man page / RFC / source reference)? -->

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] upstream `ipptool` matrix still 34/0/1 (`scripts/conformance.sh`)
- [ ] no `unsafe` outside `crates/sys`
