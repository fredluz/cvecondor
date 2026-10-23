# Path: a certificate authority is compromised or distrusted

Follow `common.md` throughout.

Every TLS client that trusts the CA is a place, not only the lines the watcher listed. Check each process's trust store, in every repo, image and server of the case:
- runtimes with their own bundled roots (Node, Bun, Deno, Java's `cacerts`): the release that drops the roots;
- language bundles (Python `certifi`, Ruby and PHP bundles) and tools that embed roots (uv, pip's vendored certifi, Go binaries): their fixed release;
- stores a tool bundles itself, which an OS store update never reaches: uv's embedded roots (unless it runs with `--native-tls`), Node's bundled store (unless `NODE_EXTRA_CA_CERTS` or `--use-system-ca` points it elsewhere), Java's `cacerts`, Go and Rust binaries built with webpki-roots, and each Docker image's own store: check which one each process actually uses;
- the OS store in each image and server (`ca-certificates` on Debian, Ubuntu, Alpine): the fixed package; a Dockerfile that installs `ca-certificates` gets it from a rebuild with `--pull --no-cache`;
- where no fixed release exists yet: distrust the roots directly (remove them from the bundle that process uses, or point it at a store without them) until it ships.

Name the roots by name and SHA-256 fingerprint from the advisory. In the report, one table lists each place, its store, whether it still trusts them, and its fix. Certificates of the user's own that the CA issued need reissuing too: check them.

What you may run follows the mode (`common.md`): fixed releases are updates (`update.md`'s rules: one branch and pull request per repo, tests, the old image kept); removing roots by hand is a workaround, done only in mode ACT; everything else is proposed. Declare waits for the stores whose fixed release hasn't shipped.
