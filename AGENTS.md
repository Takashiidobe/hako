# hako

A size-focused Rust toybox: one binary, multiple tiny utilities. Every utility must fit on a 1.44 MB floppy. That constraint drives every dependency and design decision.

## Listing Existing Utils

```
cargo run -- --list-commands
```

## Adding A Command

1. If the command needs a new dependency (clock, rng, network, etc.), define a trait for it in `src/deps/` with a real system-backed implementation and unit tests in the same file.
2. Create `src/<command>.rs`. Expose `pub fn run(...) -> io::Result<()>`. Inject traits from `src/deps/` — never call `std::fs`, sockets, or `SystemTime::now()` directly from command logic.
3. Write unit tests in the same file using small fake trait impls (see existing commands for the pattern).
4. Register the module and dispatch in `src/main.rs`. If optional, gate with a Cargo feature.
5. Run `cargo clippy` and `cargo fmt` — both must pass clean.
6. Add a man page under `man/`.

## Size Budget

- `opt-level = "z"`, `lto = true`, `strip = true`, `panic = "abort"` are already set.
- Default answer for new dependencies is **no**. Add only when the alternative is clearly worse and the size cost is justified.
- Prefer small bespoke implementations over broad framework crates.
