# Provenance: known-good sample archives

Used by `ScanEvasionIT.knownGoodOpenSourceArchivesAreNeverFlaggedAsMalicious()`.

Each file below is the exact, unmodified source archive GitHub generates for the named
project's official tag, fetched directly from `codeload.github.com` (GitHub's own archive
generation endpoint, not a third-party mirror). Nothing in these archives has been edited,
repackaged, or regenerated. Each is independently reproducible with the command shown, and
the resulting SHA-256 should match exactly, since GitHub's tag archives are deterministic
for a given tag.

| File | Project | Tag | License | SHA-256 |
|---|---|---|---|---|
| `jq-1.7.1.tar.gz` | [jqlang/jq](https://github.com/jqlang/jq) | `jq-1.7.1` | MIT | `fc75b1824aba7a954ef0886371d951c3bf4b6e0a921d1aefc553f309702d6ed1` |
| `ripgrep-14.1.0.tar.gz` | [BurntSushi/ripgrep](https://github.com/BurntSushi/ripgrep) | `14.1.0` | MIT / Unlicense (dual) | `33c6169596a6bbfdc81415910008f26e0809422fda2d849562637996553b2ab6` |
| `shellcheck-0.10.0.tar.gz` | [koalaman/shellcheck](https://github.com/koalaman/shellcheck) | `v0.10.0` | GPL-3.0 | `149ef8f90c0ccb8a5a9e64d2b8cdd079ac29f7d2f5a263ba64087093e9135050` |

## Reproduction

```bash
curl -L https://codeload.github.com/jqlang/jq/tar.gz/refs/tags/jq-1.7.1 | sha256sum
curl -L https://codeload.github.com/BurntSushi/ripgrep/tar.gz/refs/tags/14.1.0 | sha256sum
curl -L https://codeload.github.com/koalaman/shellcheck/tar.gz/refs/tags/v0.10.0 | sha256sum
```

Each command's output should match the corresponding SHA-256 above.

## Why these three

Small (460 KB to 1.3 MB each, ~2.3 MB total), actively maintained, permissively licensed,
and each ships its own LICENSE/COPYING file inside the archive, so redistributing the
unmodified archive here satisfies each project's own license terms without needing to
extract or duplicate license text separately.

## Why gzip-compressed source archives specifically, not extracted source or built binaries

`SecurityServiceImpl`'s text-pattern scanner reads uploaded content as UTF-8 text. A
gzip-compressed archive decodes to non-text byte noise under that reader, so scanning it
cannot accidentally trip a literal string pattern (`eval(`, `chmod`, etc.) the way scanning
the projects' actual extracted shell scripts or build files might. That makes these archives
a safe, low-noise choice for testing false-positive resistance against genuinely real,
unmodified third-party content, independent of what the pattern-matching layer would do
with the projects' literal source text.

This deliberately does not test extension-masquerade or executable-specific logic (see
`checkExtensionMasquerade` for that), since a `.tar.gz` is honestly extensioned and its
magic bytes are gzip's own, not an executable header. That is intentional: this fixture set
is scoped to the false-positive side of Phase 2, not a substitute for Phase 1's known-hash
coverage.

## What this is not

This is not a hash-allowlist feature test. `SecurityServiceImpl` currently has no
production known-good short-circuit, only the known-bad path via
`ThreatIntelSignatureService`. Whether to add one is a separate design decision (see
`docs/plans/real-world-testing-phase-plan.md`, Phase 2), not assumed or implemented here.
