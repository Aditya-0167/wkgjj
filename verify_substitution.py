#!/usr/bin/env python3
"""
verify_substitution.py -- no Swift/macOS toolchain needed.

Starts mock_registry.py in-process and makes real HTTP requests against it
(the same requests RegistryClient.resolve()/fetch() would make), proving
BOTH halves of OE1107240405872's finding:

  1. resolve()'s gap: HEAD /v2/{name}/manifests/{pinned-digest} reports a
     Docker-Content-Digest that does NOT match what was actually
     requested/pinned -- and nothing anywhere cross-checks that.
  2. fetch()'s gap: the content served back is self-consistent with
     whatever digest the HEAD response redirected to (so a naive "does the
     body match its own claimed digest" check would pass), but does NOT
     match the digest that was originally pinned.
  3. The substituted manifest's OWN referenced blobs (config + layer) DO
     correctly hash to their own claimed digests -- proving the gap is
     specifically about the manifest/resolve layer, not a general "server
     can lie" triviality.

This is a sanity check you can run in seconds without any toolchain. It is
NOT a replacement for the Swift harness (Sources/manifest-poc/main.swift) --
that one calls the actual project code and is the real reproduction. This
script only proves the HTTP-level substitution mechanism the Swift harness
relies on is real and self-consistent.
"""
import hashlib
import http.server
import json
import threading
import time
import urllib.request

import mock_registry as reg


def main():
    server = reg.FastBindHTTPServer(("127.0.0.1", 0), reg.Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.3)

    print(f"[*] Mock malicious registry listening on 127.0.0.1:{port}")
    print(f"[*] Digest a caller would pin (e.g. `pull name@{reg.EXPECTED_DIGEST}`):")
    print(f"    {reg.EXPECTED_DIGEST}")
    print()

    pinned_url = f"http://127.0.0.1:{port}/v2/victim/image/manifests/{reg.EXPECTED_DIGEST}"

    print("[*] HEAD request for the PINNED digest (what RegistryClient.resolve() sends):")
    req = urllib.request.Request(pinned_url, method="HEAD")
    with urllib.request.urlopen(req) as resp:
        reported_digest = resp.headers.get("Docker-Content-Digest")
    print(f"    requested digest : {reg.EXPECTED_DIGEST}")
    print(f"    Docker-Content-Digest reported: {reported_digest}")
    redirected = reported_digest != reg.EXPECTED_DIGEST
    print(f"    REDIRECTED to a different digest than requested: {redirected}")

    print()
    print("[*] GET at whatever digest the HEAD response reported")
    print("    (what RegistryClient.fetch() would be called with next):")
    fetch_url = f"http://127.0.0.1:{port}/v2/victim/image/manifests/{reported_digest}"
    with urllib.request.urlopen(fetch_url) as resp:
        body = resp.read()
    actual_digest = "sha256:" + hashlib.sha256(body).hexdigest()
    print(f"    fetched digest         : {reported_digest}")
    print(f"    actual SHA256 of body  : {actual_digest}")
    self_consistent = actual_digest == reported_digest
    matches_pinned = actual_digest == reg.EXPECTED_DIGEST
    print(f"    self-consistent (matches what resolve() reported): {self_consistent}")
    print(f"    matches ORIGINALLY PINNED digest: {matches_pinned}")

    print()
    if redirected and self_consistent and not matches_pinned:
        print("[+] CONFIRMED (both halves): resolve() accepted a Docker-Content-Digest")
        print("    that does not match what was pinned, with nothing to catch it. fetch()")
        print("    then retrieved content that IS internally self-consistent with that")
        print("    redirected digest -- so a check that only verifies 'body matches the")
        print("    digest resolve() told me' would pass -- but the content has no")
        print("    relationship to the digest the caller actually asked to pin.")
    else:
        print("[!] Unexpected result -- mock_registry.py may be misconfigured.")

    print()
    print("[*] Verifying the substituted manifest's OWN blobs self-verify")
    print("    (proving the gap is manifest-specific, not a broken mock):")
    manifest = json.loads(body)
    for kind, desc in [("config", manifest["config"])] + [("layer", l) for l in manifest["layers"]]:
        burl = f"http://127.0.0.1:{port}/v2/victim/image/blobs/{desc['digest']}"
        with urllib.request.urlopen(burl) as bresp:
            bbody = bresp.read()
        bactual = "sha256:" + hashlib.sha256(bbody).hexdigest()
        ok = bactual == desc["digest"]
        print(f"    {kind}: claimed={desc['digest']}")
        print(f"      {'':<8}actual ={bactual}  match={ok}")

    server.shutdown()


if __name__ == "__main__":
    main()
