# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2026-11-11

First public release. 0.7.0 is a pre-1.0 version: everything below is usable on
a real fleet, and the surface described in the README's *Versioning and
stability* section is what 1.0.0 will freeze.

### Added

- **Remote fleets over SSH**: one line per machine, `/proc`, `df`, the log tail
  and the `slapd.d` tree fetched over a single multiplexed connection, with the
  remote `ldapi://` socket forwarded for `cn=monitor`.
- **Groups** — named environments (`[group acc]`) selected with `--group`,
  listed with `--list-groups`; `node`, `node-file`, `uri`, `uri-file` inside a
  group replace the top-level ones.
- **`--diagnose`**: environment, SSH transport, identity, `/proc`, configuration
  files, `ldapi://` listener, socket forward, EXTERNAL bind, `cn=monitor`,
  `cn=config` and the log path, each with the fix when it fails.
- **Replication view**: per-SID `contextCSN`, the instance × SID matrix, the
  per-operation counters, and a per-SID lag that only compares instances an
  `olcSyncRepl` actually links.
- **Indexes view**: `olcDbIndex` per database, matched to the search bases by
  longest suffix, with a verdict based on the filters seen in the log.
- **Behaviour view**: `etime` per account and per filter family over a sliding
  window, with a pattern legend (`$`, `#`, `*`, `(...)+`).
- **Connections view**: client and upstream columns paired by bind DN, plus
  descriptor and ephemeral-port headroom.
- **Pixel graphs** (sixel/kitty), with a readable axis drawn in the bitmap, and
  block-rune graphs with the same axis where pixels are unavailable.
- `--json` / `--jsonl`, `--once`, `--watch`, `--probe-pixels`, `--license`,
  `--doc`.
- Crash handling that names the cause, writes a trace and restores the terminal
  instead of aborting.

### Changed

- **Replication is derived from `olcSyncRepl`**, not from the presence of a
  `contextCSN`: a value inherited from an import is not a replication state.
- `ldapi://` binds EXTERNAL by default and falls back to anonymous, saying why.
- The configuration files are the primary source; `cn=config` is a fallback.
- A node is a **machine**, not a slapd process: duplicates are discarded and
  explained on exit.

### Fixed

- `olcSyncRepl` values are read as LDIF: the `{0}` index and the quotes around
  `searchbase` made a valid agreement invisible.
- A proxy is recognised by its **real** backends, so it no longer reports a lag
  computed from the `contextCSN` it merely relays.
- A SID is only compared inside its replica set, and `olcServerID` is resolved
  by host name: the matrix no longer reports a year of lag between two pairs
  that never replicate with each other.
- The grid of a pixel graph sits on the labelled values, and the axis labels use
  one fixed 5×7 font on every screen.

### Known limitations

- Replicas are not visible without a readable `contextCSN`: `ldapi://` binds as
  the invoking user, so EXTERNAL must be allowed by the instance's ACLs.
- A proxy's `contextCSN` is the upstream's answer; it is marked, not measured.
- The TUI needs notcurses 3.0 (C API); the graphs fall back to block runes when
  the terminal offers no pixel protocol.

[Unreleased]: https://github.com/zx97/slaptop/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/zx97/slaptop/releases/tag/v0.7.0
