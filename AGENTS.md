# hako

## What This Project Is

`hako` is a small Rust "toybox"-style CLI: one binary exposes multiple tiny utilities.

The binary is size-constrained on purpose: all utilities are expected to fit on a 1.44 MB floppy. That constraint is part of the design, not an afterthought.

The dispatch model lives in [src/main.rs](/home/takashi/hako/src/main.rs). A command can be invoked in two ways:

- as the executable name itself, such as `hello` or `dig`
- as a subcommand, such as `hako hello` or `hako dig`

`main.rs` is intentionally thin. It parses argv, selects the command, constructs the real system dependencies, and calls that command's `run(...)` function.

## Source Layout

- [src/main.rs](/home/takashi/hako/src/main.rs): multi-call entrypoint and command dispatch
- [src/deps.rs](/home/takashi/hako/src/deps.rs): capability traits plus real system-backed implementations
- [src/hello.rs](/home/takashi/hako/src/hello.rs): greeting command
- [src/time.rs](/home/takashi/hako/src/time.rs): UTC clock output
- [src/rand.rs](/home/takashi/hako/src/rand.rs): random number command
- [src/overwrite.rs](/home/takashi/hako/src/overwrite.rs): file copy/overwrite utility
- [src/dig.rs](/home/takashi/hako/src/dig.rs): DNS A-record lookup
- [src/httpserver.rs](/home/takashi/hako/src/httpserver.rs): static file server with directory listing support
- [src/fetch.rs](/home/takashi/hako/src/fetch.rs): HTTP fetch command, behind the `fetch` feature
- [src/ping.rs](/home/takashi/hako/src/ping.rs): ICMP ping command, behind the `ping` feature
- [src/hash.rs](/home/takashi/hako/src/hash.rs): `md5sum` and `sha256sum`, behind the `hash` feature

The project is flat on purpose. Each command is a separate file with a narrow `run(...)` entrypoint and local tests.

## Core Design Rule

This project uses dependency injection instead of letting command modules touch the real world directly.

The important file is [src/deps.rs](/home/takashi/hako/src/deps.rs). It defines traits for side effects:

- `Clock`
- `Rng`
- `Fs`
- `DirFs`
- `Dns`
- `Net`
- `Icmp`

It also defines the real implementations:

- `SystemClock`
- `SystemRng`
- `SystemFs`
- `UdpDns`
- `SystemNet`
- `SystemIcmp`

Command modules should depend on these traits, not on `std::fs`, sockets, time, or network APIs directly. That is the main architectural constraint in this repo.

The other architectural constraint is binary size. Small bespoke code is often preferable to pulling in a large crate just to avoid writing a narrow implementation locally.

## Size Budget

This project is deliberately optimized for a tiny release binary.

- The full utility set is intended to fit on a 1.44 MB floppy.
- Heavy dependencies are a design bug unless they buy something essential.
- Standard library code and small focused implementations are preferred over broad framework crates.
- Optional functionality should stay behind Cargo features when possible.

[Cargo.toml](/home/takashi/hako/Cargo.toml) already reflects this priority with a size-oriented release profile:

- `opt-level = "z"`
- `lto = true`
- `strip = true`
- `panic = "abort"`

When proposing a new dependency, assume the default answer is no. Add it only if the alternative is clearly worse and the size cost is acceptable.

## How Commands Are Structured

Most commands follow the same shape:

1. Accept a `Write` sink for output.
2. Accept one or more injected dependency traits.
3. Accept parsed args as `&[String]` when needed.
4. Return `io::Result<()>`.

Examples:

- `time::run(out, clock)`
- `rand::run(out, rng)`
- `overwrite::run(out, fs, args)`
- `dig::run(out, dns, args)`
- `httpserver::run(out, fs, args)`

That separation matters:

- argument dispatch belongs in `main.rs`
- command behavior belongs in the command module
- OS and network integration belongs in `deps.rs`

Do not move system calls back into the command modules unless there is a strong reason. That would make the tests worse and cut across the existing design.

## Testing Style

Tests are colocated in each `src/*.rs` file under `#[cfg(test)]`.

The standard pattern is:

- allocate a `Vec<u8>` as the output buffer
- pass fake dependencies that implement the required trait
- assert on exact output or returned errors

Examples already in the tree:

- `time.rs` uses a `FixedClock`
- `rand.rs` uses a `ConstRng`
- `overwrite.rs` uses a `FakeFs`
- `dig.rs` uses `FakeDns`
- `fetch.rs` uses `FakeNet`
- `ping.rs` uses fake `Icmp` and `Dns`
- `httpserver.rs` uses a fake directory/filesystem implementation

If you add a command, keep the same pattern. Prefer small fake trait impls over integration-heavy tests.

## Feature Gates

[Cargo.toml](/home/takashi/hako/Cargo.toml) enables optional command families:

- `ping`
- `fetch`
- `hash`

Default features currently include all three plus `native-tls`.

That means:

- `fetch.rs` and `SystemNet` are conditional
- `ping.rs` and `SystemIcmp` are conditional
- `hash.rs` is conditional

When adding a feature-gated command, gate both the module import in `main.rs` and the dispatch arms.

## Notes On Existing Commands

- `dig` parses an optional `@<nameserver>` argument in `main.rs` and injects a configured `UdpDns`.
- `httpserver` is the largest command. It contains request parsing, path resolution, MIME selection, redirects for directory paths, and directory listing generation.
- `hash` reads files through `DirFs`, but reads stdin directly when the argument is `-` or no path is provided.
- `fetch` keeps HTTP behavior inside the injected network layer instead of the command itself.
- `ping` resolves hostnames through injected DNS, then sends ICMP through injected ICMP support.

## Adding A New Command

Follow the existing pattern:

1. Create `src/<command>.rs`.
2. Expose `pub fn run(...) -> io::Result<()>`.
3. Inject traits from `deps.rs` for any side effects.
4. Add focused unit tests with fake dependencies.
5. Register the module and dispatch in [src/main.rs](/home/takashi/hako/src/main.rs).
6. If optional, gate it with a Cargo feature and mirror that in `main.rs` and `deps.rs`.

Keep commands small. If a command needs real IO, networking, time, randomness, or filesystem access, put the abstraction in `deps.rs` first and inject it.

## What To Avoid

- Calling `std::fs`, socket APIs, or `SystemTime::now()` directly inside command logic when a trait should be used instead
- Putting large amounts of command-specific parsing logic into `main.rs`
- Writing tests that depend on the real network, real clock, or real filesystem unless the change explicitly requires integration coverage
- Adding heavy crates for convenience when a small local implementation would do
- Turning this into a framework-heavy CLI. The project is intentionally simple and direct.
