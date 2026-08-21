# asset-release-contracts

The format four repositories must agree on byte-for-byte: the build that signs a
release, the vendor console that stores and serves it, the supervisor that
verifies and installs it, and the ontology sidecar that publishes its own.

## What is here

- `minisign` — the signing format, verification and signing
- `writer` — the release manifest: how it is written and validated
- `component` — component naming, normalised identically by producer and verifier
- `schema_window` — what a build runs against and migrates to

## What is deliberately NOT here

**Trust anchors.** This package verifies a signature against a key it is
handed; it does not know which keys are trusted. That belongs to the verifier —
the supervisor compiles its anchors in and passes one to `minisign.verify`.

Keeping keys out means a version bump of this dependency can never change what a
deployment trusts, which is the one change nobody should be able to make by
upgrading a package.

## Why it exists

Two repositories previously kept private copies of the manifest writer. They
drifted: a port was corrected in one and not the other, and a customer's
ontology installed, started, and failed every health probe for a day because the
manifest named a port nginx already held.

## Consuming it

Pinned by tag, no registry required:

```toml
dependencies = ["asset-release-contracts @ git+https://github.com/csbogdan/asset-release-contracts@v0.1.0"]
```
