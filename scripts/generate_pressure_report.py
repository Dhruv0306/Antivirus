"""
Reads the JSON metrics written by EndpointPressureIT and ScanAccuracyIT
(target/pressure-metrics/load-metrics.json, accuracy-metrics.json) after
"mvn verify -Ppressure" finishes, and renders two committed report files:

    docs/pressure-metrics.md   a plain markdown table (diffable, readable
                                straight in the GitHub file browser)
    docs/pressure-metrics.svg  the same numbers as a styled table image,
                                embedded directly in README.md

Deliberately stdlib-only (json, pathlib, datetime), no new Python
dependency, consistent with tests/api_test.py using nothing beyond
`requests`. This script does not run the tests itself; it only renders
whatever JSON is already on disk.

Usage:
    python3 scripts/generate_pressure_report.py
"""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
METRICS_DIR = REPO_ROOT / "target" / "pressure-metrics"
DOCS_DIR = REPO_ROOT / "docs"
MD_PATH = DOCS_DIR / "pressure-metrics.md"
SVG_PATH = DOCS_DIR / "pressure-metrics.svg"


def load_json(path):
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_evasion_rows(evasion_metrics):
    """Returns (evasion_rows, false_positive_rows, evasion_detail, blind_spots,
    known_hash_rows, known_good_rows, known_good_detail)."""
    evasion_rows = []
    evasion_detail = []
    blind_spots = []
    evasion = (evasion_metrics or {}).get("evasion") if evasion_metrics else None
    if evasion:
        evasion_rows.append(("Techniques tried", str(evasion.get("totalTechniques", "-"))))
        evasion_rows.append(("Expected to still be caught", str(evasion.get("expectedCaught", "-"))))
        evasion_rows.append(("Actually caught", str(evasion.get("actuallyCaught", "-"))))
        evasion_rows.append(("Evasion resistance rate", f"{evasion.get('evasionResistanceRate', 0):.4f}"))
        evasion_rows.append(("Documented blind spots", str(evasion.get("knownBlindSpotCount", "-"))))
        for row in evasion.get("results", []):
            evasion_detail.append((row.get("technique", "-"), row.get("expectCaught"), row.get("verdict", "-"),
                                    row.get("citation", "-")))
            if not row.get("expectCaught") and not row.get("caught"):
                blind_spots.append(row.get("technique", "-"))

    false_positive_rows = []
    fp = (evasion_metrics or {}).get("falsePositive") if evasion_metrics else None
    if fp:
        false_positive_rows.append(("Legitimate scenarios tried", str(fp.get("totalScenarios", "-"))))
        false_positive_rows.append(("Flagged MALICIOUS", str(fp.get("falsePositiveCount", "-"))))
        false_positive_rows.append(("False positive rate", f"{fp.get('falsePositiveRate', 0):.4f}"))

    known_hash_rows = []
    khp = (evasion_metrics or {}).get("knownHashPathway") if evasion_metrics else None
    if khp:
        known_hash_rows.append(("Malware families covered", str(khp.get("familiesCovered", "-"))))
        known_hash_rows.append(("Families recognized", str(khp.get("familiesRecognized", "-"))))
        for family, recognized in (khp.get("knownHashCoverageByFamily") or {}).items():
            known_hash_rows.append((f"  {family}", "Recognized" if recognized else "NOT recognized"))
        known_hash_rows.append(("End-to-end hash-match verdict", str(khp.get("endToEndHashMatchVerdict", "-"))))

    known_good_rows = []
    known_good_detail = []
    kga = (evasion_metrics or {}).get("knownGoodArchive") if evasion_metrics else None
    if kga:
        known_good_rows.append(("Real open-source archives checked", str(kga.get("archivesChecked", "-"))))
        known_good_rows.append(("Flagged MALICIOUS", str(kga.get("falsePositiveCount", "-"))))
        for row in kga.get("results", []):
            known_good_detail.append((
                row.get("archive", "-"),
                row.get("honestFilenameVerdict", "-"),
                row.get("adversarialFilenameVerdict", "-"),
            ))

    return (evasion_rows, false_positive_rows, evasion_detail, blind_spots,
            known_hash_rows, known_good_rows, known_good_detail)


def pct(value):
    return f"{value:.2f}%"


def build_rows(load_metrics, accuracy_metrics):
    """Returns (load_rows, accuracy_rows) as lists of (label, value) pairs."""
    load_rows = []
    if load_metrics:
        traffic = load_metrics.get("concurrentTraffic") or {}
        scans = load_metrics.get("concurrentScans") or {}
        limiter = load_metrics.get("rateLimiter") or {}

        load_rows.append(("Concurrent unauthenticated clients", str(traffic.get("concurrentClients", "-"))))
        load_rows.append(("Requests per client", str(traffic.get("requestsPerClient", "-"))))
        load_rows.append(("Total requests", str(traffic.get("totalRequests", "-"))))
        load_rows.append(("Error rate (unauthenticated burst)", pct(traffic.get("errorRatePct", 0))))
        load_rows.append(("Max latency under load", f"{traffic.get('maxLatencyMs', '-')} ms"))
        load_rows.append(("Concurrent authenticated scans", str(scans.get("concurrentScans", "-"))))
        load_rows.append(("Error rate (concurrent scans)", pct(scans.get("errorRatePct", 0))))
        load_rows.append(("Scan history entries after burst", str(scans.get("historyTotalElements", "-"))))
        load_rows.append(("Rate-limiter burst size", str(limiter.get("burstSize", "-"))))
        load_rows.append(("Requests rejected (HTTP 429)", str(limiter.get("rateLimitedCount", "-"))))

    accuracy_rows = []
    if accuracy_metrics:
        matrix = accuracy_metrics.get("confusionMatrix") or {}
        verdicts = accuracy_metrics.get("verdictBreakdown") or {}
        tier = accuracy_metrics.get("maliciousLabeledTierSplit") or {}

        accuracy_rows.append(("Total synthetic files scanned", str(accuracy_metrics.get("totalFiles", "-"))))
        accuracy_rows.append(("Scan requests that errored", str(accuracy_metrics.get("scanErrors", "-"))))
        accuracy_rows.append(("True positive", str(matrix.get("truePositive", "-"))))
        accuracy_rows.append(("False positive", str(matrix.get("falsePositive", "-"))))
        accuracy_rows.append(("True negative", str(matrix.get("trueNegative", "-"))))
        accuracy_rows.append(("False negative", str(matrix.get("falseNegative", "-"))))
        accuracy_rows.append(("Accuracy", f"{accuracy_metrics.get('accuracy', 0):.4f}"))
        accuracy_rows.append(("Precision", f"{accuracy_metrics.get('precision', 0):.4f}"))
        accuracy_rows.append(("Recall", f"{accuracy_metrics.get('recall', 0):.4f}"))
        accuracy_rows.append(("F1 score", f"{accuracy_metrics.get('f1', 0):.4f}"))
        accuracy_rows.append(("Verdict: MALICIOUS", str(verdicts.get("MALICIOUS", "-"))))
        accuracy_rows.append(("Verdict: SUSPICIOUS", str(verdicts.get("SUSPICIOUS", "-"))))
        accuracy_rows.append(("Verdict: CLEAN", str(verdicts.get("CLEAN", "-"))))
        accuracy_rows.append(("Malicious-labeled detected as MALICIOUS", str(tier.get("detectedAsMalicious", "-"))))
        accuracy_rows.append(("Malicious-labeled detected as SUSPICIOUS", str(tier.get("detectedAsSuspicious", "-"))))

    return load_rows, accuracy_rows


def render_markdown(generated_at, load_rows, accuracy_rows, evasion_rows, false_positive_rows,
                     evasion_detail, blind_spots, known_hash_rows, known_good_rows, known_good_detail):
    lines = [
        "# Pressure and accuracy metrics",
        "",
        f"_Last generated: {generated_at} (UTC), by `.github/workflows/pressure-test.yml`._",
        "",
        "Regenerated automatically on every scheduled or manually-dispatched run of the pressure suite "
        "(`mvn verify -Ppressure`). See `EndpointPressureIT.java` and `ScanAccuracyIT.java` under "
        "`src/test/java/com/antivirus/pressure/` for what each number below actually measures, and "
        "`scripts/generate_pressure_report.py` for how this file and `pressure-metrics.svg` are rendered "
        "from the raw JSON in `target/pressure-metrics/`.",
        "",
        "## Load and concurrency",
        "",
        "| Metric | Value |",
        "|---|---|",
    ]
    for label, value in load_rows:
        lines.append(f"| {label} | {value} |")
    if not load_rows:
        lines.append("| _No load-metrics.json found_ | - |")

    lines += [
        "",
        "## Detection accuracy (synthetic labeled corpus)",
        "",
        "| Metric | Value |",
        "|---|---|",
    ]
    for label, value in accuracy_rows:
        lines.append(f"| {label} | {value} |")
    if not accuracy_rows:
        lines.append("| _No accuracy-metrics.json found_ | - |")

    lines += [
        "",
        "**Note:** the accuracy corpus is generated in memory at test time, not sourced from any real "
        "malware collection. Malicious-labeled samples are built to trip specific scoring signals in "
        "`SecurityServiceImpl` (EICAR known-hash match, ransomware extension/text pattern, trojan filename "
        "signature, rootkit text pattern); benign-labeled samples contain none of those signals. This "
        "measures whether the engine's own designed-for signals still fire correctly, not real-world "
        "malware coverage.",
        "",
        "## Evasion resistance (adversarial synthetic corpus)",
        "",
        "| Metric | Value |",
        "|---|---|",
    ]
    for label, value in evasion_rows:
        lines.append(f"| {label} | {value} |")
    if not evasion_rows:
        lines.append("| _No evasion-metrics.json found_ | - |")

    lines += [
        "",
        "**Note:** see `ScanEvasionIT.java` under `src/test/java/com/antivirus/pressure/`. This measures "
        "how well the engine holds up against synthetic files engineered to exploit its own published "
        "detection logic (keyword fragmentation, base64-hidden payload text, benign filenames wrapping "
        "malicious-shaped content, an oversized file placing its trigger text past the 10MB pattern-scan "
        "cap), not against any real malware sample. Techniques the engine's own logic already accounts for "
        "(double-extension masquerade, ransomware-extension case variation) are asserted against; documented "
        "blind spots are reported, not asserted, since hiding a known gap by asserting around it would defeat "
        "the point of tracking it.",
        "",
    ]

    if evasion_detail:
        lines += ["| Technique | Expected caught | Actual verdict | Citation |", "|---|---|---|---|"]
        for technique, expect_caught, verdict, citation in evasion_detail:
            lines.append(
                f"| {technique} | {'Yes' if expect_caught else 'Known blind spot'} | {verdict} | {citation} |")
        lines.append("")

    if blind_spots:
        lines += [
            "**Currently open blind spots:** " + "; ".join(blind_spots) + ". "
            "Tracked here deliberately rather than hidden by the test; each one is a candidate for a "
            "future detection improvement.",
            "",
        ]

    lines += [
        "## False-positive resistance (legitimate content)",
        "",
        "| Metric | Value |",
        "|---|---|",
    ]
    for label, value in false_positive_rows:
        lines.append(f"| {label} | {value} |")
    if not false_positive_rows:
        lines.append("| _No falsePositive section in evasion-metrics.json_ | - |")

    lines += [
        "",
        "**Note:** legitimate sysadmin scripts, backup-tool documentation, and developer notes that happen "
        "to mention things like `Runtime.exec`, `chmod 777`, `eval(`, or plain sockets. A MALICIOUS verdict "
        "here is treated as a hard failure; that is the failure mode that erodes user trust in a real "
        "product fastest.",
        "",
    ]
    lines += [
        "## Known-malware hash coverage (real published IOCs)",
        "",
        "| Metric | Value |",
        "|---|---|",
    ]
    for label, value in known_hash_rows:
        lines.append(f"| {label} | {value} |")
    if not known_hash_rows:
        lines.append("| _No knownHashPathway section in evasion-metrics.json_ | - |")

    lines += [
        "",
        "**Note:** each family's SHA-256 is a real, published IOC hash, never an actual payload. See "
        "`ScanEvasionIT.KNOWN_MALWARE_IOCS` for per-entry source citations (MalwareBazaar, US-CERT, "
        "cross-referenced vendor research). This measures hash-lookup coverage across distinct families, "
        "not detection of any live sample.",
        "",
        "## Known-good real-world archive resistance",
        "",
        "| Metric | Value |",
        "|---|---|",
    ]
    for label, value in known_good_rows:
        lines.append(f"| {label} | {value} |")
    if not known_good_rows:
        lines.append("| _No knownGoodArchive section in evasion-metrics.json_ | - |")

    lines += [
        "",
        "**Note:** these are real, unmodified GitHub tag source archives for well-known open-source "
        "projects (jq, ripgrep, shellcheck), not synthetic content, see "
        "`src/test/resources/known-good-samples/PROVENANCE.md` for exact provenance and independent "
        "reproduction commands. Each is scanned under both its honest filename and a deliberately "
        "adversarial one; a SUSPICIOUS verdict on the adversarial filename is expected and correct "
        "(the engine flagging a suspicious name for review), a MALICIOUS verdict on either is a hard "
        "failure, since real, legitimate open-source software must never be convicted outright by name "
        "alone.",
        "",
    ]

    if known_good_detail:
        lines += ["| Archive | Honest filename verdict | Adversarial filename verdict |", "|---|---|---|"]
        for archive, honest_verdict, adversarial_verdict in known_good_detail:
            lines.append(f"| {archive} | {honest_verdict} | {adversarial_verdict} |")
        lines.append("")

    return "\n".join(lines)


def esc(text):
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def render_svg_table(title, rows, y_offset, width):
    row_height = 26
    header_height = 34
    height = header_height + row_height * len(rows) + 12
    col1_x = 16
    col2_x = width - 16

    parts = [
        f'<rect x="0" y="{y_offset}" width="{width}" height="{height}" '
        f'fill="#0d1117" stroke="#30363d" rx="6"/>',
        f'<text x="{col1_x}" y="{y_offset + 23}" font-family="Segoe UI, Helvetica, Arial, sans-serif" '
        f'font-size="15" font-weight="600" fill="#58a6ff">{esc(title)}</text>',
        f'<line x1="0" y1="{y_offset + header_height}" x2="{width}" y2="{y_offset + header_height}" '
        f'stroke="#30363d"/>',
    ]
    for i, (label, value) in enumerate(rows):
        row_y = y_offset + header_height + i * row_height
        if i % 2 == 1:
            parts.append(f'<rect x="0" y="{row_y}" width="{width}" height="{row_height}" fill="#161b22"/>')
        text_y = row_y + row_height - 8
        parts.append(
            f'<text x="{col1_x}" y="{text_y}" font-family="Consolas, Menlo, monospace" '
            f'font-size="12.5" fill="#c9d1d9">{esc(label)}</text>'
        )
        parts.append(
            f'<text x="{col2_x}" y="{text_y}" font-family="Consolas, Menlo, monospace" '
            f'font-size="12.5" fill="#7ee787" text-anchor="end" font-weight="600">{esc(value)}</text>'
        )
    return "\n".join(parts), height


def render_svg(generated_at, load_rows, accuracy_rows, evasion_rows=None):
    width = 640
    y = 16
    blocks = []

    load_svg, load_h = render_svg_table("Load and concurrency", load_rows, y, width)
    blocks.append(load_svg)
    y += load_h + 16

    accuracy_svg, accuracy_h = render_svg_table("Detection accuracy", accuracy_rows, y, width)
    blocks.append(accuracy_svg)
    y += accuracy_h + 8

    if evasion_rows:
        y += 8
        evasion_svg, evasion_h = render_svg_table("Evasion resistance", evasion_rows, y, width)
        blocks.append(evasion_svg)
        y += evasion_h + 8

    footer_y = y + 14
    total_height = footer_y + 12

    svg = (
        f'<svg viewBox="0 0 {width} {total_height}" width="{width}" height="{total_height}" '
        f'xmlns="http://www.w3.org/2000/svg">\n'
        f'<rect x="0" y="0" width="{width}" height="{total_height}" fill="#010409"/>\n'
        + "\n".join(blocks) + "\n"
        f'<text x="16" y="{footer_y}" font-family="Consolas, Menlo, monospace" font-size="10.5" '
        f'fill="#6e7681">Generated {esc(generated_at)} (UTC + 5:30)</text>\n'
        "</svg>\n"
    )
    return svg


def main():
    load_metrics = load_json(METRICS_DIR / "load-metrics.json")
    accuracy_metrics = load_json(METRICS_DIR / "accuracy-metrics.json")
    evasion_metrics = load_json(METRICS_DIR / "evasion-metrics.json")

    if load_metrics is None and accuracy_metrics is None and evasion_metrics is None:
        print(
            "No metrics JSON found under target/pressure-metrics/. "
            "Run \"mvn verify -Ppressure\" first.",
            file=sys.stderr,
        )
        sys.exit(1)

    accuracy_data = (accuracy_metrics or {}).get("accuracy") if accuracy_metrics else None
    load_rows, accuracy_rows = build_rows(load_metrics, accuracy_data)
    (evasion_rows, false_positive_rows, evasion_detail, blind_spots,
     known_hash_rows, known_good_rows, known_good_detail) = build_evasion_rows(evasion_metrics)

    # Use IST timezone for generated_at timestamp to match the timezone used in the GitHub Actions workflow.
    ist = timezone(timedelta(hours=5, minutes=30))
    generated_at = datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S")

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    MD_PATH.write_text(
        render_markdown(generated_at, load_rows, accuracy_rows, evasion_rows, false_positive_rows,
                         evasion_detail, blind_spots, known_hash_rows, known_good_rows, known_good_detail),
        encoding="utf-8")
    SVG_PATH.write_text(render_svg(generated_at, load_rows, accuracy_rows, evasion_rows), encoding="utf-8")

    print(f"Wrote {MD_PATH.relative_to(REPO_ROOT)}")
    print(f"Wrote {SVG_PATH.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
