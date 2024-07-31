dkcli
===

Command-line installer for AOSC OS with a prompt-based interface.

Usage
---

```
Usage: dkcli [OPTIONS]

Options:
  -c, --config <CONFIG>  Set install config path
  -h, --help             Print help
```

Dependencies
---

### Build-time

- Rust (rustc)

### Runtime

- C and C++ runtimes (usually glibc and libgcc)
- OpenSSL (libcrypto and libssl)
- Zlib (libz)

Building
---

Simply build with Cargo:

```
cargo build --release
```

The resulting binary executable will be available at:

```
./target/release/dkcli
```
