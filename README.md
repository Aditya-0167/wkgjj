# PoC for OE1107240405872 — manifest/index content not verified against digest

**Confirmed, on real macOS, via two independent CI runs:** `ImageStore.pull()`
— the exact API `container pull` uses — imports content under a completely
different digest than the one that was pinned in the reference string, with
no error anywhere in the chain. Pinned digest and actually-imported digest
(`image.digest`) are different values in both runs. Raw logs from both are
in `ci-results/`.

Apple's reviewer closed the original report with a specific, fair
objection: *"The included script does not call the affected code; it
represents the absence of a check rather than testing the real code path.
We are therefore not able to confirm from the material provided whether a
substituted manifest would in fact be accepted."*

This package answers that directly: it calls the **real** project code
(`RegistryClient.fetch`, `RegistryClient.fetchData`, `ImageStore.pull`)
against a minimal malicious/compromised registry, and runs it on real macOS
via CI — the same approach that got OE1107563755116 (the ext4 report)
re-evaluated.

**Two rounds of testing went into this, and both results are reported
honestly.** The first round substituted only the manifest *body* while
leaving the `HEAD` response internally consistent with what was requested —
under that setup, `RegistryClient.fetch()` was confirmed unverified (Part
1), but the full `ImageStore.pull()` (Part 2) actually rejected the attack
with a digest-mismatch error. Tracing why: `import()` (which `pull()`
calls) always fetches-and-verifies a descriptor via the verified
`fetchAll()` path *before* `walk()` ever reads it back through the
unverified fallback — so for a same-digest substitution, the unverified
path never actually gets reached in a normal pull. That was a real and
useful finding, not a failure — it meant the first framing of "impact" was
too broad, and it's worth knowing the specific narrower shape got tested
and rejected before landing on this one.

The version in this package tests the *actual* full attack the original
report described, including its "compounding" half:
`resolve()` returns a `Docker-Content-Digest` that doesn't match what was
requested at all, and the substituted content is self-consistent with
*that* redirected digest — meaning `fetchAll()`'s own self-consistency
check has nothing to catch, since it only ever checks content against
whatever `resolve()` told it, never against what the caller originally
pinned.

## What's in this package

- **`mock_registry.py`** — a minimal malicious OCI registry. It computes the
  SHA256 of a legitimate-looking manifest (`EXPECTED_MANIFEST_BYTES` — this
  is the digest a caller would pin) and, regardless of what digest is
  actually requested: on `HEAD` (what `resolve()` uses), reports a
  **different** `Docker-Content-Digest` (`SUBSTITUTED_DIGEST`); on `GET` at
  either the originally-pinned digest or the redirected one, serves a
  **different** manifest body (`SUBSTITUTED_MANIFEST_BYTES`) referencing
  attacker-chosen config/layer blobs, which correctly self-hashes to
  `SUBSTITUTED_DIGEST`. Those attacker blobs are served correctly and
  self-consistently at `/v2/{name}/blobs/{digest}` (blob-level verification
  is real and enforced by the project; the gap is specifically at the
  manifest/resolve layer, and the PoC only claims what's actually true
  there).
- **`verify_substitution.py`** — no Swift/macOS needed. Starts the mock
  registry in-process and makes the same HTTP requests
  `RegistryClient.resolve()`/`fetch()` would, proving both halves of the
  HTTP-level substitution mechanism (the resolve() redirect, and the
  self-consistent-but-wrong body) before you even get to Swift.
- **`Sources/manifest-poc/main.swift`** — the real reproduction. Two parts:
  1. Calls `RegistryClient.fetch(name:descriptor:)` directly with a
     `Descriptor` pinned to the *expected* digest, against the mock
     registry. Shows it returns successfully with the *substituted*
     manifest, no error. Then independently fetches the same URL as raw
     bytes and hashes it, to show explicitly that the body doesn't match
     what was requested — using the project's own `SHA256.Digest
     .digestString` helper (`ContainerizationOCI/Content/SHA256+Extensions.swift`),
     the exact comparison `ImageStore+Import.swift` uses for blobs.
  2. Calls `ImageStore(path:).pull(reference:insecure:)` — the exact public
     API `container pull` uses — with a digest-pinned reference pointed at
     the mock registry, which now also redirects via `resolve()`. Compares
     `image.digest` (what actually got imported) against the digest that
     was pinned in the reference string, to show explicitly whether they
     differ.
- **`.github/workflows/poc.yml`** — runs the above on GitHub's hosted macOS
  runner (real Apple-provided VM), starting the mock registry as a
  background process, then running the harness against it, capturing full
  output.

## How to run it

### Option A — GitHub Actions (recommended, real macOS)

1. Push this whole folder's contents to a GitHub repo (root-level —
   `Package.swift`, `mock_registry.py`, `.github/`, `Sources/`, etc. all at
   the top, not nested in a subfolder).
2. Actions tab → `manifest-poc` → Run workflow.
3. Check the run's Summary for full output, or download the
   `manifest-poc-macos-log` artifact.

### Option B — no Swift needed, sanity-check the mechanism first

```bash
python3 verify_substitution.py
```

Confirms the HTTP-level substitution (HEAD reports the pinned digest, GET
returns non-matching content, the substituted manifest's own blobs
self-verify) in a few seconds, no toolchain required.

### Option C — run the Swift harness yourself on a Mac

```bash
python3 mock_registry.py 0    # note the printed MOCK_REGISTRY_PORT and EXPECTED_DIGEST
swift build
.build/debug/manifest-poc <port> <expectedDigest>
```

## Actual confirmed output (real, from `ci-results/`, not hypothetical)

This is the real output from two independent GitHub Actions runs
(`ci-results/poc-results-run1.log`, `ci-results/poc-results-run2.log`),
both on macOS 26 / Xcode 26 / Swift 6.3.3, both with the identical result:

Part 1:

```
[+] client.fetch() returned SUCCESSFULLY -- no digest-mismatch error was thrown.
    Returned manifest has 1 layer(s).
    layers[0].digest = sha256:3dcebf49f57af6e1e54d6bb68aebfaf6b39edb5e40e2f67ff9c1c5c71efcb0c3
    config.digest    = sha256:55a07f9076b8ec37d9d5c7bd506476bcfaf1e05ace56e56b3472d9b32743f83d
[*] Independently fetching the SAME URL as raw bytes via client.fetchData()
    requested digest       : sha256:d63bef6166a2e069af5b947e09aacb183fc83e0d4aceb84d8b1bab31017b122f
    actual SHA256 of body  : sha256:ddf5beee9f2dbf915d777a58aaabfc612722ce3338c71f45bb536f854eb13476
[+] CONFIRMED: the response body does NOT hash to the digest it was
    requested/pinned by. client.fetch() above accepted and decoded it anyway.
```

Part 2 — the full `pull()`:

```
[*] Calling store.pull(reference: "127.0.0.1:PORT/victim/image@sha256:d63bef6166a2e069af5b947e09aacb183fc83e0d4aceb84d8b1bab31017b122f", insecure: true)
[+] pull() SUCCEEDED. No digest-mismatch error at any point.
    pinned digest (what the reference asked for) = sha256:d63bef6166a2e069af5b947e09aacb183fc83e0d4aceb84d8b1bab31017b122f
    image.digest  (what actually got imported)   = sha256:0acf091b8deeb8a2695e4b4b75e77515af55ffcd2e4570ca5731ba9469a3af64

[+] IMPACT CONFIRMED: a pull pinned to one digest silently imported
    a completely different, attacker-chosen manifest and its referenced
    layers, with no error anywhere in the chain. Nothing checked that
    the actually-imported digest matched the one that was pinned.
```

The pinned digest (`...b122f`) and the imported `image.digest`
(`...3af64`) are different values — that's the whole finding, stated as
plainly as possible: pin one thing, silently get another, zero errors,
confirmed twice independently.

## Source confirmation (pulled fresh from `apple/containerization` `main`
before building this)

`import()` (called by `ImageStore.pull`) always verifies a descriptor via
the *verified* `fetchAll()` path before `walk()` can read it through the
*unverified* fallback — but nothing anywhere compares the digest
`resolve()` returns against the digest the caller actually asked to pin,
which is the gap this version of the PoC exercises directly:

`RegistryClient+Fetch.swift` — `fetch<T: Codable>` has no verification at
all:

```swift
public func fetch<T: Codable>(name: String, descriptor: Descriptor) async throws -> T {
    ...
    components.path = "/v2/\(name)/\(resource)/\(descriptor.digest)"
    ...
    return try await requestJSON(components: components, headers: headers)
}
```

`resolve(name:tag:)` — accepts whatever `Docker-Content-Digest` the server
sends, never compared against what was requested:

```swift
public func resolve(name: String, tag: String) async throws -> Descriptor {
    ...
    let digest = try ParsedDigest(parsing: header).description
    ...
    return Descriptor(mediaType: type, digest: digest, size: size)
}
```

`ImageStore+Import.swift` — confirms the asymmetry exactly. Blob content is
verified:

```swift
private func fetchBlob(_ descriptor: Descriptor) async throws {
    ...
    let (_, digest) = try await client.fetchBlob(name: name, descriptor: descriptor, into: tempFile, progress: progress)
    guard digest.digestString == descriptor.digest else {
        throw ContainerizationError(.internalError, message: "digest mismatch")
    }
    ...
}
```

Manifest/index content is not — `getManifestContent` falls straight
through to the unverified `client.fetch`:

```swift
private func getManifestContent<T: Sendable & Codable>(descriptor: Descriptor) async throws -> T {
    ...
    return try await self.client.fetch(name: name, descriptor: descriptor)
}
```

`ImageStore.swift`'s `pull(reference:...)` confirms the report's
"compounding" claim — `ref.digest` (the pinned digest from
`name@sha256:...`) is passed straight into `resolve(name:tag:)` as `tag`,
and `resolve()`'s own result is never cross-checked against it:

```swift
guard let tag = ref.tag ?? ref.digest else { ... }
let rootDescriptor = try await client.resolve(name: name, tag: tag)
```

All of this matches the original report's claims exactly; nothing here
required any correction to the underlying analysis, only a real
executing demonstration of it.
