# Follow-ups from the Rust clients work

Date: 31/10/2026.

The Rust clients live in `Dhruv0306/SecureGuard-Clients`: the detection engine `secureguard-core`,
the `scg-scan` command line tool and the desktop app. Building them found things that belong to
this repository. This page collects all of them in one place so nothing depends on remembering a
conversation.

It was checked against `main` at commit `6ef8dd0`; line numbers below refer to that commit.
**Nothing here was compiled or run.** The Java snippets for fixes 1 to 3 come from the Rust
repository's own notes, and the ones for fixes 4 and 5 are sketches written from the Rust fixes.
Build and test each one in this repository before relying on it.

## Status at a glance

| # | Item | Status in this repository |
|---|---|---|
| 1 | Entropy scoring flags every `.jar` and `.msi` | Not fixed (checked) |
| 2 | Weak text patterns can convict a file on their own | Not fixed (checked) |
| 3 | A Linux `.so` inside a Windows program is called a disguised executable | Not fixed (checked) |
| 4 | The ransomware folder score is given to every file in the folder | Not fixed. The Java method has both bugs the Rust one had (checked) |
| 5 | Text patterns and the folder score can convict a file on their own | Not fixed. Several scoring paths are affected (checked) |
| 6 | abuse.ch now requires an Auth-Key | Already handled in `ThreatIntelSignatureService`. Setup is not documented, and the Rust clients use a different variable name |
| 7 | Zip entry scoring | Already correct, no change |

## Why these exist

A release-build system scan of a developer's Windows machine on 15/10/2026 (11,508 files in 5
minutes) flagged 528 files: 497 suspicious and 31 malicious. Nearly all were legitimate: IDE
extension `.jar` and `.js` files, vendor driver archives and install scripts, bundled native
libraries. A second scan on 26/10/2026 (after the first round of fixes) found 5 Malicious files in
57,000 scanned, all false positives, which led to fixes 4 and 5. The scan engine worked. The scoring
rules did not hold up at that scale.

The Rust engine was fixed first. The same scoring rules were ported to Rust from
`SecurityServiceImpl`, so the Java engine has the same problems. Until it is fixed, the two engines
disagree on the five cases below, and Rust is the less suspicious one. That is intended. A comparison
of the two engines on a `.jar` or `.msi` with high entropy, a script with only weak patterns, a native
library with a matching header, a file next to a note and a cluster of unfamiliar extensions, or a
file whose only evidence is text patterns will show Java as more suspicious.

## 1. False-positive fixes to port

Suggested order: 1, 2 and 3 are small and independent. Do 4, then 5. Add the tests to
`SecurityServiceImplTest` with each fix.

### Fix 1: entropy scoring flags every `.jar` and `.msi`

`.jar` and `.msi` are in `SUSPICIOUS_EXTENSIONS` (line 198), which switches entropy scoring on
(`isExecutableLikeForEntropy`, line 839). Both formats are compressed by design, so their entropy is
always high and each one gets `SCORE_HIGH_ENTROPY` (30), which is a SUSPICIOUS verdict by itself
(`THRESHOLD_SUSPICIOUS` is 25).

Change: a compressed container is only entropy-checked if its header is really a Windows or Linux
executable.

```java
private static final Set<String> COMPRESSED_CONTAINER_EXTENSIONS = Set.of(".jar", ".msi");

private boolean isExecutableLikeForEntropy(String extensionLowerCase, byte[] header) {
    if (containsSuspiciousBytes(header)) {
        return true;
    }
    return SUSPICIOUS_EXTENSIONS.contains(extensionLowerCase)
            && !COMPRESSED_CONTAINER_EXTENSIONS.contains(extensionLowerCase);
}
```

Tests to add: a high-entropy `library.jar` and `Setup.msi` score CLEAN; a high-entropy `packed.bin`
is still SUSPICIOUS; a file named `fake.jar` that starts with `MZ` is still entropy-checked.

### Fix 2: weak text patterns can convict a file on their own

`MAX_WEAK_PATTERN_SCORE` is 32 (line 251), above the suspicious threshold of 25. Weak patterns
(`eval(`, `fromCharCode`, `document.write` and similar) appear in ordinary bundled JavaScript, so any
such file was SUSPICIOUS, and with one strong pattern on top (32 + 30 = 62) it was MALICIOUS.

Change: cap weak patterns just below the threshold, so they add to a verdict but never produce one
alone.

```java
private static final int MAX_WEAK_PATTERN_SCORE = THRESHOLD_SUSPICIOUS - 1; // 24
```

`THRESHOLD_SUSPICIOUS` is declared at line 289, after `MAX_WEAK_PATTERN_SCORE` at line 251. Java does
not allow a forward reference in a static initializer, so either move the constant below the
thresholds or write the literal 24.

Tests to add: a text with many weak patterns scores CLEAN but above 0; the same text plus
`powershell -w hidden -Command x` is SUSPICIOUS (24 + 30 = 54), not MALICIOUS.

### Fix 3: an ELF `.so` is called a disguised executable

`checkExtensionMasquerade` (line 824) returns `SCORE_EXTENSION_MASQUERADE` (70) for any executable
header behind an extension that is not in `SUSPICIOUS_EXTENSIONS`. `.so` is not in the list, so every
Linux shared library bundled inside a Windows program (the Python debugger ships several) was
MALICIOUS.

Change: an executable whose header matches the kind its name promises is expected.

```java
private boolean isExpectedNativeLibrary(String nameLowerCase, byte[] header) {
    boolean elf = header.length >= 4 && header[0] == 0x7f && header[1] == 'E'
            && header[2] == 'L' && header[3] == 'F';
    boolean pe = header.length >= 2 && header[0] == 'M' && header[1] == 'Z';
    String ext = getFileExtension(new File(nameLowerCase)).toLowerCase();
    boolean elfName = ext.equals(".so") || ext.equals(".ko") || ext.equals(".o")
            || ext.equals(".node") || nameLowerCase.contains(".so.");
    boolean peName = ext.equals(".pyd") || ext.equals(".node");
    return (elf && elfName) || (pe && peName);
}
```

Call it before `checkExtensionMasquerade` at lines 514 (`scanFile`) and 1618 (`detectMalware`) and
skip the score when it is true. A Windows executable named `.so`, or an ELF named `report.pdf`, must
still be flagged.

Tests to add: `libfoo.so`, `libfoo.so.1.2.3`, `mod.ko` and `addon.node` with an ELF header are CLEAN;
`report.pdf` with an ELF header is MALICIOUS.

### Fix 4: the ransomware folder score is given to every file in the folder

`scoreRansomwareDirectoryBehavior` (line 1539) adds `SCORE_RANSOMWARE_DIR_BEHAVIOR` (55) when a
folder has a ransom-note-like name (`readme` with `txt`, `recovery`, `how_to_decrypt`, and so on) and
five entries that share an unfamiliar extension. Checked in this repository, it has both bugs the
Rust version had:

- It returns the score for **every file** in the folder, because it only looks at the parent folder
  and never at which file it was asked about.
- It lists the folder with `parentDir.listFiles()`, which includes **subfolders**, and takes each
  one's "extension" from its name, so `six-1.16.0.dist-info` counts as a `.dist-info` entry.

Measured in the Rust engine on a developer machine:

| Folder | Why it qualified | Effect |
|---|---|---|
| Python `site-packages` | `README.txt` plus many `*.dist-info` folders | `six.py`: folder 55 + one weak pattern 8 = 63, MALICIOUS |
| `reportlab/fonts` | `00readme.txt` plus 18 `.afm`, 18 `.pfb`, 5 `.ttf` files | every file in the folder scored 55 |

Change: count regular files only, and give the score only to the files it is about: the note-like
files and the files whose extension forms a cluster of five or more. Rust reference: `FolderBehavior`
and `score_for` in `core/src/dir_behavior.rs` of `SecureGuard-Clients`. Sketch (check it against that
file before use):

```java
private int scoreRansomwareDirectoryBehavior(File file) {
    File parentDir = file.getParentFile();
    if (parentDir == null || !parentDir.exists()) {
        return 0;
    }
    File[] files = dirListingCache.get()
            .computeIfAbsent(parentDir.getAbsolutePath(), k -> parentDir.listFiles());
    if (files == null) {
        return 0;
    }

    boolean hasRansomNote = false;
    Map<String, Integer> unknownExtCounts = new HashMap<>();
    for (File f : files) {
        if (!f.isFile()) {
            continue; // subfolders are not entries
        }
        if (isRansomNoteName(f.getName().toLowerCase())) {
            hasRansomNote = true;
        }
        String ext = getFileExtension(f).toLowerCase();
        if (!ext.isEmpty() && !COMMON_EXTENSIONS.contains(ext) && !RANSOMWARE_EXTENSIONS.contains(ext)) {
            unknownExtCounts.merge(ext, 1, Integer::sum);
        }
    }
    if (!hasRansomNote) {
        return 0;
    }
    Set<String> clusterExtensions = new HashSet<>();
    unknownExtCounts.forEach((ext, count) -> {
        if (count >= 5) {
            clusterExtensions.add(ext);
        }
    });
    if (clusterExtensions.isEmpty()) {
        return 0;
    }

    String ownName = file.getName().toLowerCase();
    boolean aboutThisFile = isRansomNoteName(ownName)
            || clusterExtensions.contains(getFileExtension(file).toLowerCase());
    return aboutThisFile ? SCORE_RANSOMWARE_DIR_BEHAVIOR : 0;
}
// isRansomNoteName: the existing readme+txt / how_to_decrypt / recovery /
// help_decrypt / decrypt_instructions test, moved out of the loop.
```

The method is called from `scanFile` (line 534), `detectRansomware` (line 1525) and `detectMalware`
(line 1629); the change is inside the method, so all three get it. The folder listing stays cached
per folder.

Tests to add: a folder with `README.txt`, five `*.dist-info` subfolders and `six.py` scores 0 for
`six.py`; in a folder with a note and five `.xyz123` files, the note and the `.xyz123` files score 55
and `main.py` scores 0.

### Fix 5: text patterns and the folder score can convict a file on their own

Both are circumstantial. They describe a file's wording or surroundings, not the file, and a
document that talks about malware matches them as well as malware does. Measured in the Rust engine:
a handoff document that mentions a hidden PowerShell window and a "ransom note" scored 30 + 8 + 45 =
83; a bundled `app.js` with two strong patterns scored 60 + 24 = 84; a font license with the joke
"Vera cannot become a ransom note font" scored 45 + 55 = 100. All were MALICIOUS.

Change: when no signal about the file itself contributed, hold the total at 59 (SUSPICIOUS).

- Signals about the file itself (direct): `EXTENSION_MASQUERADE`, `HIGH_ENTROPY_EXECUTABLE`,
  `RANSOMWARE_EXTENSION`, `TROJAN_NAME_SIGNATURE`, `ROOTKIT_BINARY_IN_DRIVER_LOCATION`,
  `ZIP_CONTAINS_EXECUTABLE_ENTRY`, and a known hash (which already returns early in `scanFile`). The
  Rust engine also counts a YARA match; this engine has no YARA.
- Circumstantial: `STRONG_CODE_PATTERN`, `WEAK_CODE_PATTERN`, `RANSOMWARE_NOTE_TEXT`,
  `RANSOMWARE_DIRECTORY_BEHAVIOR` and `ROOTKIT_TEXT_PATTERN`.

The signal names are the same in both engines. In `scanFile(File, String)` (lines 508 to 565) the score is a plain
sum, so the cap goes just before `Math.min(score, 100)` at line 565:

```java
private static final int MAX_CIRCUMSTANTIAL_ONLY_SCORE = THRESHOLD_MALICIOUS - 1; // 59

// directSignal is set to true wherever a direct signal above adds to the score.
if (!directSignal) {
    score = Math.min(score, MAX_CIRCUMSTANTIAL_ONLY_SCORE);
}
```

The same sum, with the same flaw, is also in `detectMalware` (line 1609), `detectTrojan` (line
1578) and `detectRansomware` (line 1515), which return a boolean. Apply the cap in each of them, or
they will still report a pattern-only file as malicious while `scanFile` reports it as suspicious.

Tests to add: two strong patterns plus four weak ones in `bundle.js` is SUSPICIOUS at 59; the folder
score plus one weak pattern is SUSPICIOUS; a strong pattern in `report.locked` and in
`backdoor_tool.js` is still MALICIOUS (the extension and the file name are direct signals).

Check the existing tests before changing anything: any test in `SecurityServiceImplTest` that
expects MALICIOUS from patterns or note text alone will need a direct signal added. In the pressure
tests, `ScanAccuracyIT` counts a file as flagged when it is SUSPICIOUS or MALICIOUS, so the flagged
counts should not move, but its tier split (`detectedAsMalicious` against `detectedAsSuspicious`)
may. `docs/pressure-metrics.md` is regenerated by CI, so look at that after the first run.

## 2. Zip entry scoring: already correct

The Rust engine added the zip entry score (15) **per matching entry** and ran on any file whose bytes
looked like a zip; a driver archive with 29 `.dll` entries scored 435 and was convicted. This engine
adds it **once** (line 560) and only for names ending in `.zip`, `.jar` or `.war` (`isZipFile`, line
738). Rust now matches this engine. No change here.

## 3. The abuse.ch Auth-Key

MalwareBazaar's keyless export URL now answers HTTP 410 Gone, and its exports need a free Auth-Key
from <https://auth.abuse.ch/>. `ThreatIntelSignatureService` already handles this:

- the default URL is `https://mb-api.abuse.ch/v2/files/exports/{authKey}/recent.csv`, and the
  `{authKey}` token is replaced at request time;
- the key comes from `app.threat-intel.auth-key`, falling back to the `ABUSECH_AUTH_KEY`
  environment variable;
- without a key the feed is skipped with a warning that says where to get one;
- the key is URL-encoded, never logged, and removed from exception messages;
- the nightly `threat-intel-feed-check.yml` workflow reads it from the `ABUSECH_AUTH_KEY` repository
  secret and fails fast when it is missing.

What is missing or different:

- **Setup is not written down.** `README.md` does not mention the key. It now has a short note under
  "Key environment variables".
- **The name differs from the Rust clients.** This repository uses `ABUSECH_AUTH_KEY`; `SecureGuard-Clients`
  uses `ABUSE_CH_AUTH_KEY`, chosen there, and reads it from a `.env` file. Using one name in both
  would be simpler for anyone who runs both; changing the Rust side to also accept `ABUSECH_AUTH_KEY`
  is a small change if wanted.
- **Facts learned from the Rust client's real run (30/10/2026), useful for this service:**
  - the recent CSV export parsed with the same 64-hex-character pattern, 1,038 new hashes;
  - a wrong key answers HTTP 401;
  - abuse.ch refreshes the recent export every 5 minutes, it covers the last 48 hours, and it asks
    not to be fetched more often than that.
- **Refresh frequency.** Here the feed is fetched on an admin's `updateVirusDefinitions()` call and,
  if `app.threat-intel.refresh-on-startup` is true, at startup. There is no scheduler, so the 5-minute
  limit is only a concern if that endpoint is called repeatedly. It is worth knowing if a schedule
  is ever added.

## 4. Not fixed in either engine

Observed in the same scans and not addressed:

- install scripts (`.cmd`) that use `powershell -w hidden`, which is a strong pattern
- `.exe` installers and some `.dll` files whose entropy is high because they are packed or contain
  compressed payloads
- JSON, log and source-map files that contain weak patterns
- bundled JavaScript that contains one strong pattern (SUSPICIOUS after fix 5, no longer MALICIOUS)
- files whose text really matches a pattern, such as a document about malware or a license that jokes
  about a "ransom note": SUSPICIOUS (59) after fix 5
- font and other asset folders with a readme still score 55 for the readme and the files with the
  clustered extension (`.afm`, `.pfb`) after fix 4; adding those extensions to `COMMON_EXTENSIONS`
  would stop it

Larger fixes to consider later: trust for signed binaries (Authenticode), known-good hash lists, and
a per-folder trust list. Re-running a system scan after these changes shows how much is left.

## Where the Rust side is recorded

In `SecureGuard-Clients`: `docs/java-engine-false-positive-fixes.md` (the same five fixes from the
Rust point of view), `docs/phase2-threat-intel-sync-plan.md` (the feed and its Auth-Key update) and
`CHANGELOG.md`.
