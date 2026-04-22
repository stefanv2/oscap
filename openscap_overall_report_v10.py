#!/usr/bin/env python3
"""
openscap_overall_report_v8.py
==============================
Genereert een technisch HTML-rapport én een management HTML-rapport op basis
van OpenSCAP XCCDF-resultatenbestanden en een gemapt uitzonderingen-CSV.

Vereiste invoer:
  --base-dir    Map met serverresultaten. Verwacht: <base-dir>/<server>/*_latest_results.xml
  --mapped-csv  Output-CSV van map_exceptions_to_oscap_v3.py
  --manual-csv  Handmatige mapping-CSV (voor telling in rapport)
  --output      Pad naar technisch HTML-rapport (management naast hetzelfde pad)

Gebruik:
  python openscap_overall_report_v8.py \
      --base-dir  /scans \
      --mapped-csv /data/mapped_exceptions.csv \
      --manual-csv /data/manual_mapping.csv \
      --output    /reports/openscap_technical.html \
      --stale-days 8 \
      --low-risk-threshold 50
"""
from __future__ import annotations

import argparse
import csv
import html
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuratie-constanten
# ---------------------------------------------------------------------------

# Standaard drempel voor LOW RISK: aantal open FAIL-findings
DEFAULT_LOW_RISK_THRESHOLD: int = 50

# Standaard maximaal aantal top-offenders te tonen
TOP_OFFENDERS_N: int = 10

# Sorteervolgorde van statussen (laagste getal = hoogste prioriteit)
STATUS_SORT_ORDER: dict[str, int] = {
    "ERROR":         0,
    "NON-COMPLIANT": 1,
    "LOW RISK":      2,
    "COMPLIANT":     3,
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Één OSCAP finding (fail, accepted, dormant, etc.) voor een server."""
    rule_id: str
    title: str
    severity: str
    raw_result: str
    effective_status: str
    reason: str = ""
    source_scope: str = ""
    source_server: str = ""


@dataclass
class ServerResult:
    """Alle parseer- en analyseresultaten voor één server."""
    server: str
    profile: str
    os_version: str
    score: str
    score_value: float | None
    start_time: str
    end_time: str
    fail_open: int
    fail_accepted: int
    fail_not_applicable: int
    exception_not_triggered: int
    not_in_profile: int
    not_executed: int
    error: int
    unknown: int
    notchecked: int
    pass_count: int
    status: str
    stale: bool
    age_days: int | None
    xml_path: str
    html_path: str
    findings: list[Finding] = field(default_factory=list)
    dormant: list[Finding] = field(default_factory=list)
    not_in_profile_items: list[Finding] = field(default_factory=list)
    not_executed_items: list[Finding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# HTML-hulpfuncties
# ---------------------------------------------------------------------------

def esc(v: str) -> str:
    """HTML-escape een waarde; None of leeg → lege string."""
    return html.escape(v or "")


def div(css_class: str, content: str) -> str:
    """Rendert een <div> met een CSS-klasse; retourneert leeg als content leeg is."""
    return f"<div class='{css_class}'>{content}</div>" if content else ""


def span(css_class: str, content: str) -> str:
    """Rendert een <span> met een CSS-klasse."""
    return f'<span class="{css_class}">{content}</span>'


def badge(css_class: str, label: str) -> str:
    """Rendert een badge-span."""
    return span(f"badge {css_class}", esc(label))


# ---------------------------------------------------------------------------
# CSS-constanten (gescheiden van Python-logica)
# ---------------------------------------------------------------------------

CSS_SHARED = """
body {
  font-family: Arial, Helvetica, sans-serif;
  margin: 20px;
  color: #1f2937;
  background: #f7f8fb;
}
h1, h2 { margin-bottom: 8px; }
.small { font-size: 0.92rem; color: #4b5563; }

/* ── Kaarten-grid ────────────────────────────────────────────────────────── */
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
  margin: 18px 0 24px 0;
}
.card {
  background: #fff;
  border: 1px solid #dbe1ea;
  border-left: 6px solid #cbd5e1;
  border-radius: 12px;
  padding: 14px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.04);
}
.card .label { font-size: 0.84rem; color: #556070; margin-bottom: 6px; }
.card .value { font-size: 1.7rem; font-weight: 700; }
.card.fail         { border-left-color: #dc2626; }
.card.accepted     { border-left-color: #0284c7; }
.card.na           { border-left-color: #6366f1; }
.card.dormant      { border-left-color: #a855f7; }
.card.notinprofile { border-left-color: #f59e0b; }
.card.notexecuted  { border-left-color: #14b8a6; }
.card.ok           { border-left-color: #16a34a; }
.card.err          { border-left-color: #b91c1c; }
.card.lowrisk      { border-left-color: #0ea5e9; }
.card.warn         { border-left-color: #f59e0b; }

/* ── Panel ───────────────────────────────────────────────────────────────── */
.panel {
  background: #fff;
  border: 1px solid #dbe1ea;
  border-radius: 12px;
  padding: 16px;
  margin: 18px 0;
}

/* ── Hoofdtabel: horizontaal scrollbaar, sticky header ───────────────────── */
.table-wrap {
  width: 100%;
  overflow-x: auto;               /* horizontaal scrollen op smalle schermen  */
  -webkit-overflow-scrolling: touch;
  border: 1px solid #dbe1ea;
  border-radius: 10px;
}
.table-wrap table {
  /* breedte wordt bepaald door de inhoud, niet door het venster */
  width: max-content;
  min-width: 100%;
  border-collapse: collapse;
  background: #fff;
}
/* Sticky header werkt alleen correct als de tabel in een scrollbare wrapper zit */
.table-wrap th {
  position: sticky;
  top: 0;
  z-index: 2;
  white-space: nowrap;            /* voorkomt afbreken van kolomlabels        */
}

/* Inner-tabellen (top-offenders, unmatched) hoeven niet te scrollen */
.inner-table {
  width: 100%;
  margin-top: 8px;
  border-collapse: collapse;
  background: #fff;
  border: 1px solid #dbe1ea;
  border-radius: 10px;
  overflow: hidden;
}

th, td {
  border-top: 1px solid #e5e7eb;
  padding: 8px 10px;
  text-align: left;
  vertical-align: top;
}
th { background: #eef2f7; }

/* Cijferkolommen (telwaarden) smal en gecentreerd */
td.num, th.num {
  text-align: center;
  white-space: nowrap;
  padding: 8px 6px;
}

/* Telwaarden: mini-tabel met label links, waarde rechts */
.counts-table {
  border-collapse: collapse;
  font-size: 0.82rem;
  width: 100%;
}
.counts-table td {
  padding: 2px 4px;
  border: none;
  vertical-align: middle;
  white-space: nowrap;
}
.counts-table tr + tr td { border-top: 1px solid #f1f5f9; }
.ct-label { color: #6b7280; padding-right: 6px; }
.ct-val   { font-weight: 700; text-align: right; min-width: 28px; }
.ct-red   { color: #b91c1c; }
.ct-green { color: #166534; }
.ct-dim   { color: #9ca3af; font-weight: 400; }

/* ── Badges en severity-labels ───────────────────────────────────────────── */
.badge, .sev {
  display: inline-block;
  border-radius: 999px;
  padding: 3px 9px;
  font-size: 0.76rem;
  font-weight: 700;
  white-space: nowrap;
}
.ok             { background: #dcfce7; color: #166534; }
.warn           { background: #fef3c7; color: #92400e; }
.bad            { background: #fee2e2; color: #991b1b; }
.neutral        { background: #e5e7eb; color: #374151; }
.lowrisk        { background: #e0f2fe; color: #075985; }
.fresh          { background: #dcfce7; color: #166534; }
.stale          { background: #fee2e2; color: #991b1b; }
.accepted       { background: #dbeafe; color: #1d4ed8; }
.na             { background: #e0e7ff; color: #4338ca; }
.dormant        { background: #f3e8ff; color: #7e22ce; }
.not-in-profile { background: #fef3c7; color: #92400e; }
.not-executed   { background: #ccfbf1; color: #115e59; }
.fail-open      { background: #fee2e2; color: #991b1b; }
.sev-high       { background: #fee2e2; color: #991b1b; }
.sev-medium     { background: #fef3c7; color: #92400e; }
.sev-low        { background: #dcfce7; color: #166534; }
.sev-unknown    { background: #e5e7eb; color: #374151; }

/* ── Score-badge ─────────────────────────────────────────────────────────── */
.score {
  display: inline-block;
  padding: 3px 9px;
  border-radius: 8px;
  font-weight: 700;
  white-space: nowrap;
}
.score-ok      { background: #dcfce7; color: #166534; }
.score-warn    { background: #fef3c7; color: #92400e; }
.score-bad     { background: #fee2e2; color: #991b1b; }
.score-unknown { background: #e5e7eb; color: #374151; }

/* ── Tooltip voor profiel-ID ─────────────────────────────────────────────── */
.tip {
  position: relative;
  display: inline-block;
  cursor: help;
  border-bottom: 1px dashed #94a3b8;
  font-size: 0.78rem;
  color: #475569;
}
.tip .tip-text {
  visibility: hidden;
  opacity: 0;
  width: max-content;
  max-width: 420px;
  background: #1e293b;
  color: #f1f5f9;
  font-size: 0.78rem;
  border-radius: 6px;
  padding: 6px 10px;
  position: absolute;
  z-index: 10;
  top: 130%;
  left: 0;
  word-break: break-all;
  transition: opacity 0.15s;
  pointer-events: none;
}
.tip:hover .tip-text {
  visibility: visible;
  opacity: 1;
}

/* ── Finding-details (inklapbaar) ────────────────────────────────────────── */
details.findings-details {
  margin: 6px 0;
  background: #f9fafb;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  padding: 7px 10px;
}
details.findings-details summary { cursor: pointer; font-weight: 600; font-size: 0.88rem; }
.finding-list { margin: 8px 0 0 16px; padding: 0; }
.finding-list li { margin-bottom: 8px; font-size: 0.88rem; }

/* ── Overige hulpklassen ─────────────────────────────────────────────────── */
.muted { color: #6b7280; font-size: 0.85rem; }
.legend {
  background: #fff;
  border: 1px solid #dbe1ea;
  border-radius: 12px;
  padding: 14px;
  margin-bottom: 18px;
}
.legend-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 8px;
}
a { color: #0f4c81; text-decoration: none; }
a:hover { text-decoration: underline; }
"""

HTML_PAGE_TEMPLATE = """\
<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{css}</style>
</head>
<body>
{body}
</body>
</html>
"""


# ---------------------------------------------------------------------------
# CSV-hulpfuncties
# ---------------------------------------------------------------------------

def sniff_delimiter(sample: str) -> str:
    """Detecteert het CSV-scheidingsteken automatisch."""
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        return dialect.delimiter
    except Exception:
        if ";" in sample:
            return ";"
        if "\t" in sample:
            return "\t"
        return ","


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    """Leest een CSV in als lijst van genormaliseerde dicts."""
    raw = path.read_text(encoding="utf-8-sig", errors="replace")
    delimiter = sniff_delimiter(raw[:4096])
    reader = csv.DictReader(raw.splitlines(), delimiter=delimiter)

    rows: list[dict[str, str]] = []
    for row in reader:
        cleaned: dict[str, str] = {}
        for k, v in row.items():
            key = (k or "").strip()
            if isinstance(v, list):
                val = " ".join(str(x).strip() for x in v if x is not None).strip()
            else:
                val = (v or "").strip()
            cleaned[key] = val
        rows.append(cleaned)
    return rows


# ---------------------------------------------------------------------------
# Uitzondering-mapping inladen
# ---------------------------------------------------------------------------

def load_exception_mapping(
    mapped_csv: Path,
) -> tuple[dict[str, list[dict[str, str]]], list[dict[str, str]]]:
    """
    Laadt de gemapte uitzonderingen-CSV en groepeert ze per MATCHED_RULE_ID.

    Retourneert:
      - mapping:   rule_id → lijst van uitzondering-dicts
      - unmatched: rijen zonder geldig MATCHED_RULE_ID
    """
    rows = read_csv_rows(mapped_csv)
    mapping: dict[str, list[dict[str, str]]] = {}
    unmatched: list[dict[str, str]] = []

    for row in rows:
        rid = row.get("MATCHED_RULE_ID", "").strip()
        if not rid:
            unmatched.append(row)
            continue

        mapping.setdefault(rid, []).append({
            "status":       row.get("SUGGESTED_DASHBOARD_STATUS", "").strip() or "ACCEPTED",
            "reason":       row.get("REASON", "").strip(),
            "rule_name":    row.get("RULE_NAME", "").strip(),
            "match_status": row.get("MATCH_STATUS", "").strip(),
            "match_comment":row.get("MATCH_COMMENT", "").strip(),
            "source_scope": row.get("SOURCE_SCOPE", "").strip(),
            "source_server":row.get("SOURCE_SERVER", "").strip(),
        })

    return mapping, unmatched


# ---------------------------------------------------------------------------
# XML-hulpfuncties
# ---------------------------------------------------------------------------

def get_namespace(tag: str) -> str:
    """Extraheert de XML-namespace uit een element-tag."""
    return tag.split("}")[0] + "}" if "}" in tag else ""


def text_or_empty(elem, path: str) -> str:
    """Geeft de getrimde tekst van een sub-element terug, of een lege string."""
    if elem is None:
        return ""
    val = elem.findtext(path, default="")
    return " ".join(val.split()) if val else ""


# ---------------------------------------------------------------------------
# Datum/tijd-hulpfuncties
# ---------------------------------------------------------------------------

def parse_iso_datetime(value: str) -> datetime | None:
    """Parseert een ISO-datetime string naar een datetime-object."""
    if not value or value == "n/a":
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def parse_score_value(score: str) -> float | None:
    """Converteert een score-string naar float; None bij fout."""
    try:
        return float(score)
    except Exception:
        return None


def format_datetime_nl(value: str) -> str:
    """Formatteert een ISO-datetime naar leesbare NL-notatie (dd-mm-yyyy HH:MM)."""
    dt = parse_iso_datetime(value)
    if dt is None:
        return value or "n/a"
    return dt.strftime("%d-%m-%Y %H:%M")


# ---------------------------------------------------------------------------
# Classificatiefuncties
# ---------------------------------------------------------------------------

def severity_order(sev: str) -> int:
    """Numerieke prioriteit voor severiteitsortering (laag getal = hogere prioriteit)."""
    return {"high": 0, "medium": 1, "low": 2, "unknown": 3}.get(
        (sev or "unknown").lower(), 9
    )


def score_class(score_value: float | None) -> str:
    """CSS-klasse op basis van OSCAP-score."""
    if score_value is None:
        return "score-unknown"
    if score_value < 70:
        return "score-bad"
    if score_value < 90:
        return "score-warn"
    return "score-ok"


def status_class(status: str) -> str:
    """CSS-klasse voor een serverstatus-badge."""
    return {
        "COMPLIANT":     "ok",
        "LOW RISK":      "lowrisk",
        "NON-COMPLIANT": "warn",
        "ERROR":         "bad",
    }.get(status, "neutral")


def finding_status_class(status: str) -> str:
    """CSS-klasse voor een finding-badge."""
    return {
        "FAIL":              "fail-open",
        "ACCEPTED":          "accepted",
        "NOT_APPLICABLE":    "na",
        "DORMANT_EXCEPTION": "dormant",
        "NOT_IN_PROFILE":    "not-in-profile",
        "NOT_EXECUTED":      "not-executed",
    }.get(status, "neutral")


def determine_status(
    error: int,
    fail_open: int,
    unknown: int,
    notchecked: int,
    low_risk_threshold: int = DEFAULT_LOW_RISK_THRESHOLD,
) -> str:
    """
    Bepaalt de overall serverstatus.

    Volgorde:
      1. ERROR  → één of meer scanfouten
      2. COMPLIANT  → geen open findings, geen unknown/notchecked
      3. LOW RISK   → fail_open ≤ drempel, geen unknown/notchecked
      4. NON-COMPLIANT → alle overige gevallen
    """
    if error > 0:
        return "ERROR"
    if fail_open == 0 and unknown == 0:
        return "COMPLIANT"
    if fail_open <= low_risk_threshold and unknown == 0:
        return "LOW RISK"
    return "NON-COMPLIANT"


# ---------------------------------------------------------------------------
# OS-versie-detectie
# ---------------------------------------------------------------------------

def detect_os_version(
    profile_id: str,
    xml_path: Path,
    root,
    ns: str,
) -> str:
    """
    Detecteert de Oracle Linux-versie (OL8/OL9) uit de XML-metadata.
    Zoekt in: profile_id, bestandsnaam, mapnaam, root-id, titel en platform-tags.
    """
    blob_parts = [
        profile_id or "",
        xml_path.name,
        str(xml_path.parent),
        root.get("id", ""),
        root.findtext(f".//{ns}title", default=""),
        " ".join(p.get("idref", "") for p in root.findall(f".//{ns}platform")),
    ]
    blob = " ".join(blob_parts).lower()

    if "oracle linux 9" in blob or "ol-9" in blob or "ol9" in blob:
        return "OL9"
    if "oracle linux 8" in blob or "ol-8" in blob or "ol8" in blob:
        return "OL8"
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Server-scope filtering
# ---------------------------------------------------------------------------

def filter_exceptions_for_server(
    target_server: str,
    exceptions_by_rule_id: dict[str, list[dict[str, str]]],
) -> dict[str, dict[str, str]]:
    """
    Selecteert per rule_id de meest specifieke uitzondering voor de doelserver.
    Server-specifieke uitzonderingen hebben voorrang boven globale ('ALL') uitzonderingen.
    """
    target_norm = (target_server or "").strip().lower()
    filtered: dict[str, dict[str, str]] = {}

    for rid, candidates in exceptions_by_rule_id.items():
        chosen = None
        all_candidate = None

        for exc in candidates:
            scope  = (exc.get("source_scope", "") or "").strip().upper()
            server = (exc.get("source_server", "") or "").strip().lower()

            if scope == "SERVER":
                if server == target_norm:
                    chosen = exc
                    break
            else:
                all_candidate = exc

        if chosen is not None:
            filtered[rid] = chosen
        elif all_candidate is not None:
            filtered[rid] = all_candidate

    return filtered


# ---------------------------------------------------------------------------
# XML-parsing (opgesplitst in kleinere functies)
# ---------------------------------------------------------------------------

def _parse_test_result_meta(
    test_result,
    ns: str,
    xml_path: Path,
) -> dict:
    """
    Extraheert metadata uit het TestResult-element:
    profile_id, target, start_time, end_time, score.
    """
    meta = {
        "profile_id":  "",
        "target":      xml_path.parent.name,
        "start_time":  "n/a",
        "end_time":    "n/a",
        "score":       "n/a",
    }
    if test_result is None:
        return meta

    profile_elem = test_result.find(f"{ns}profile")
    if profile_elem is not None:
        meta["profile_id"] = profile_elem.get("idref", "")

    target_text = text_or_empty(test_result, f"{ns}target")
    if target_text:
        meta["target"] = target_text.split(".")[0]

    meta["start_time"] = test_result.get("start-time", "n/a")
    meta["end_time"]   = test_result.get("end-time", "n/a")

    score_elem = test_result.find(f"{ns}score")
    if score_elem is not None and score_elem.text:
        meta["score"] = " ".join(score_elem.text.split())

    return meta


def _build_rule_defs(root, ns: str) -> dict[str, dict]:
    """
    Bouwt een opzoekdict van rule_id → {title, severity, selected}
    vanuit alle Rule-elementen in de XML.
    """
    rule_defs: dict[str, dict] = {}
    for rule in root.findall(f".//{ns}Rule"):
        rid = rule.get("id", "")
        if not rid:
            continue
        rule_defs[rid] = {
            "title":    text_or_empty(rule, f"{ns}title"),
            "severity": (rule.get("severity", "unknown") or "unknown").lower(),
            "selected": (rule.get("selected", "") or "").lower(),
        }
    return rule_defs


def _categorize_findings(
    root,
    ns: str,
    applicable_exceptions: dict[str, dict],
    rule_defs: dict[str, dict],
) -> dict:
    """
    Verwerkt alle rule-resultaten en categoriseert findings in:
      - findings:              regels die FAILen (open of met uitzondering)
      - dormant:               uitzonderingen die nu niet geactiveerd zijn
      - not_in_profile_items:  uitzonderingen voor regels buiten dit profiel
      - not_executed_items:    uitzonderingen voor niet-uitgevoerde regels
      - counts:                Counter van alle raw resultaten

    Retourneert een dict met de vier lijsten en de Counter.
    """
    counts: Counter = Counter()
    findings: list[Finding] = []
    dormant: list[Finding] = []
    not_in_profile_items: list[Finding] = []
    not_executed_items: list[Finding] = []
    result_map: dict[str, str] = {}

    # Verwerk alle rule-resultaten
    for rr in root.findall(f".//{ns}rule-result"):
        rid = rr.get("idref", "")
        res = text_or_empty(rr, f"{ns}result").lower() or "unknown"
        counts[res] += 1
        result_map[rid] = res

        if res == "fail":
            meta = rule_defs.get(rid, {})
            exc  = applicable_exceptions.get(rid, {})
            findings.append(Finding(
                rule_id=rid,
                title=meta.get("title", "") or "(geen titel)",
                severity=meta.get("severity", "unknown"),
                raw_result=res,
                effective_status=exc.get("status", "FAIL") or "FAIL",
                reason=exc.get("reason", ""),
                source_scope=exc.get("source_scope", ""),
                source_server=exc.get("source_server", ""),
            ))

    # Verwerk uitzonderingen die niet getriggerd zijn (rule faalt niet)
    for rid, exc in applicable_exceptions.items():
        if any(f.rule_id == rid for f in findings):
            continue   # al verwerkt als fail

        res      = result_map.get(rid, "")
        meta     = rule_defs.get(rid, {})
        title    = meta.get("title", "") or exc.get("rule_name", "(geen titel)")
        severity = meta.get("severity", "unknown")
        selected = meta.get("selected", "")

        if res == "notselected" or selected == "false":
            not_in_profile_items.append(Finding(
                rule_id=rid, title=title, severity=severity,
                raw_result=res or "notselected",
                effective_status="NOT_IN_PROFILE",
                reason=exc.get("reason", ""),
                source_scope=exc.get("source_scope", ""),
                source_server=exc.get("source_server", ""),
            ))
        elif res in ("pass", "fixed", "informational", "notapplicable"):
            dormant.append(Finding(
                rule_id=rid, title=title, severity=severity,
                raw_result=res,
                effective_status="DORMANT_EXCEPTION",
                reason=exc.get("reason", ""),
                source_scope=exc.get("source_scope", ""),
                source_server=exc.get("source_server", ""),
            ))
        elif res in ("notchecked", "unknown", "error") or rid in result_map or rid in rule_defs:
            not_executed_items.append(Finding(
                rule_id=rid, title=title, severity=severity,
                raw_result=res or "unclassified",
                effective_status="NOT_EXECUTED",
                reason=exc.get("reason", ""),
                source_scope=exc.get("source_scope", ""),
                source_server=exc.get("source_server", ""),
            ))

    # Sorteer alle lijsten: severity → titel → rule_id
    sort_key = lambda x: (severity_order(x.severity), x.title.lower(), x.rule_id.lower())
    for lst in (findings, dormant, not_in_profile_items, not_executed_items):
        lst.sort(key=sort_key)

    return {
        "findings":             findings,
        "dormant":              dormant,
        "not_in_profile_items": not_in_profile_items,
        "not_executed_items":   not_executed_items,
        "counts":               counts,
        "result_map":           result_map,
    }


def parse_results_xml(
    xml_path: Path,
    stale_days: int,
    exceptions_by_rule_id: dict[str, list[dict[str, str]]],
    low_risk_threshold: int = DEFAULT_LOW_RISK_THRESHOLD,
) -> ServerResult:
    """
    Parseert één XCCDF-resultatenbestand naar een ServerResult-object.
    Koppelt uitzonderingen en berekent statussen.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns   = get_namespace(root.tag)

    test_result = root.find(f".//{ns}TestResult")
    meta = _parse_test_result_meta(test_result, ns, xml_path)

    os_version           = detect_os_version(meta["profile_id"], xml_path, root, ns)
    applicable_exceptions = filter_exceptions_for_server(meta["target"], exceptions_by_rule_id)
    rule_defs            = _build_rule_defs(root, ns)

    cat = _categorize_findings(root, ns, applicable_exceptions, rule_defs)

    counts              = cat["counts"]
    findings            = cat["findings"]
    dormant             = cat["dormant"]
    not_in_profile_items= cat["not_in_profile_items"]
    not_executed_items  = cat["not_executed_items"]

    fail_open           = sum(1 for f in findings if f.effective_status == "FAIL")
    fail_accepted       = sum(1 for f in findings if f.effective_status == "ACCEPTED")
    fail_not_applicable = sum(1 for f in findings if f.effective_status == "NOT_APPLICABLE")
    error               = counts.get("error", 0)
    unknown             = counts.get("unknown", 0)
    notchecked          = counts.get("notchecked", 0)

    status = determine_status(error, fail_open, unknown, notchecked, low_risk_threshold)

    # Scan-leeftijd berekenen
    dt = parse_iso_datetime(meta["start_time"])
    age_days = None
    stale    = False
    if dt is not None:
        now      = datetime.now(dt.tzinfo or timezone.utc)
        delta    = now - dt
        age_days = delta.days
        stale    = delta.days >= stale_days

    html_candidate = xml_path.with_name(xml_path.name.replace("_results.xml", "_report.html"))

    return ServerResult(
        server=meta["target"],
        profile=meta["profile_id"],
        os_version=os_version,
        score=meta["score"],
        score_value=parse_score_value(meta["score"]),
        start_time=meta["start_time"],
        end_time=meta["end_time"],
        fail_open=fail_open,
        fail_accepted=fail_accepted,
        fail_not_applicable=fail_not_applicable,
        exception_not_triggered=len(dormant),
        not_in_profile=len(not_in_profile_items),
        not_executed=len(not_executed_items),
        error=error,
        unknown=unknown,
        notchecked=notchecked,
        pass_count=counts.get("pass", 0),
        status=status,
        stale=stale,
        age_days=age_days,
        xml_path=str(xml_path),
        html_path=str(html_candidate) if html_candidate.exists() else "",
        findings=findings,
        dormant=dormant,
        not_in_profile_items=not_in_profile_items,
        not_executed_items=not_executed_items,
    )


# ---------------------------------------------------------------------------
# HTML-blokken opbouwen (technisch rapport)
# ---------------------------------------------------------------------------

def _render_finding_item(f: Finding, badge_label: str | None) -> str:
    """Rendert één finding als <li>-element."""
    badge_html = badge(finding_status_class(f.effective_status), badge_label) + " " if badge_label else ""
    raw_div    = div("muted", f"Resultaat: {esc(f.raw_result)}")
    reason_div = div("muted", f"Reden: {esc(f.reason)}" if f.reason else "")

    if f.source_scope == "SERVER":
        source_div = div("muted", f"Bron: server override ({esc(f.source_server)})")
    elif f.source_server:
        source_div = div("muted", f"Bron: {esc(f.source_server)}")
    elif f.source_scope:
        source_div = div("muted", f"Bron: {esc(f.source_scope)}")
    else:
        source_div = ""

    return (
        f"<li>{badge_html}"
        f'<span class="sev sev-{esc((f.severity or "unknown").lower())}">'
        f'{esc((f.severity or "unknown").upper())}</span> '
        f"<strong>{esc(f.title)}</strong>"
        f"{div('muted', esc(f.rule_id))}"
        f"{raw_div}{reason_div}{source_div}</li>"
    )


def build_list_block(
    title: str,
    items: list[Finding],
    badge_label: str | None = None,
) -> str:
    """
    Rendert een inklapbare <details>-sectie met een lijst van findings.
    Retourneert een lege string als er geen items zijn.
    """
    if not items:
        return ""
    lis = "".join(_render_finding_item(f, badge_label) for f in items)
    return (
        f"<details class='findings-details'>"
        f"<summary>{esc(title)} ({len(items)})</summary>"
        f"<ul class='finding-list'>{lis}</ul>"
        f"</details>"
    )


def build_findings_block(item: ServerResult) -> str:
    """Rendert alle finding-categorieën voor één server als HTML."""
    open_findings     = [f for f in item.findings if f.effective_status == "FAIL"]
    accepted_findings = [f for f in item.findings if f.effective_status == "ACCEPTED"]
    na_findings       = [f for f in item.findings if f.effective_status == "NOT_APPLICABLE"]

    parts = [
        build_list_block("Open findings",                        open_findings,            "FAIL OPEN"),
        build_list_block("Accepted findings",                    accepted_findings,         "ACCEPTED"),
        build_list_block("Not applicable findings",              na_findings,               "NOT APPLICABLE"),
        build_list_block("Exceptions aanwezig maar niet actief", item.dormant,              "EXCEPTION NOT TRIGGERED"),
        build_list_block("Exceptions buiten dit profiel",        item.not_in_profile_items, "NOT IN PROFILE"),
        build_list_block("Exceptions niet uitgevoerd",           item.not_executed_items,   "NOT EXECUTED"),
    ]
    parts = [p for p in parts if p]
    return "".join(parts) if parts else '<span class="muted">geen</span>'


def build_top_offenders(items: list[ServerResult], top_n: int = TOP_OFFENDERS_N) -> str:
    """
    Bouwt een tabel met de meest voorkomende open FAIL-findings over alle servers.
    Gesorteerd op aantal getroffen servers (aflopend).
    """
    counter:      Counter        = Counter()
    title_map:    dict[str, str] = {}
    severity_map: dict[str, str] = {}

    for item in items:
        seen: set[str] = set()
        for f in item.findings:
            if f.effective_status != "FAIL" or f.rule_id in seen:
                continue
            seen.add(f.rule_id)
            counter[f.rule_id] += 1
            title_map[f.rule_id]    = f.title
            severity_map[f.rule_id] = f.severity

    if not counter:
        return "<p>Geen open findings gevonden.</p>"

    rows = []
    for rid, count in counter.most_common(top_n):
        sev = severity_map.get(rid, "unknown")
        rows.append(
            f"<tr>"
            f"<td>{count}</td>"
            f"<td>"
            f'<span class="sev sev-{esc(sev.lower())}">{esc(sev.upper())}</span>'
            f"</td>"
            f"<td>"
            f"<strong>{esc(title_map.get(rid, '(geen titel)'))}</strong>"
            f"{div('muted', esc(rid))}"
            f"</td>"
            f"</tr>"
        )

    return (
        "<table class='inner-table'>"
        "<thead><tr><th>Servers</th><th>Severity</th><th>Rule</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )


def build_unmatched_block(unmatched_rows: list[dict[str, str]]) -> str:
    """Rendert een tabel van uitzonderingen die niet gematcht konden worden."""
    if not unmatched_rows:
        return "<p>Geen unmatched exceptions.</p>"

    rows = []
    for row in unmatched_rows:
        rows.append(
            "<tr>"
            f"<td>{esc(row.get('RULE_NAME', ''))}</td>"
            f"<td>{esc(row.get('REASON', ''))}</td>"
            f"<td>{esc(row.get('MATCH_STATUS', ''))}</td>"
            f"<td>{esc(row.get('MATCH_COMMENT', ''))}</td>"
            "</tr>"
        )

    return (
        "<table class='inner-table'>"
        "<thead><tr><th>Rule naam</th><th>Reden</th><th>Match status</th><th>Toelichting</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )


def _render_score_html(score_value: float | None, score_text: str) -> str:
    """Rendert een score-badge."""
    if score_value is not None:
        display = f"{score_value:.2f}".replace(".", ",")
        return span(f"score {score_class(score_value)}", display)
    return span("score score-unknown", "n/a")


def _render_profile_tooltip(profile: str) -> str:
    """
    Rendert het profiel-ID als een verkorte tekst met een hover-tooltip.
    De volledige profiel-ID is vaak lang (xccdf_org.ssgproject.content_profile_stig),
    dus we tonen alleen het gedeelte na 'profile_' en zetten de volledige ID in de tooltip.
    """
    if not profile:
        return '<span class="muted">—</span>'
    short = profile.split("profile_")[-1] if "profile_" in profile else profile
    return (
        f'<span class="tip">{esc(short)}'
        f'<span class="tip-text">{esc(profile)}</span>'
        f'</span>'
    )


def _render_counts_grid(item: ServerResult) -> str:
    """
    Rendert telwaarden als een mini-tabel: één rij per categorie,
    label links uitgelijnd, waarde rechts.

    Kleurlogica:
      - Rood + vet  → waarden die aandacht vragen (FAIL, ERROR, UNKNOWN, NOTCHECKED)
      - Groen + vet → positieve waarden (PASS, ACCEPTED, NOT APPLICABLE)
      - Grijs       → informatieve nullen of secundaire categorieën
    Nullen bij probleemcategorieën worden gedimd weergegeven zodat
    de lezer direct ziet wat relevant is.
    """

    def _row(label: str, n: int, style: str) -> str:
        """Één tabelrij: <label> | <waarde met kleurklasse>."""
        if style == "red":
            val_html = (
                f'<span class="ct-val ct-red">{n}</span>'
                if n > 0
                else f'<span class="ct-val ct-dim">{n}</span>'
            )
        elif style == "green":
            val_html = (
                f'<span class="ct-val ct-green">{n}</span>'
                if n > 0
                else f'<span class="ct-val ct-dim">{n}</span>'
            )
        else:  # "dim" — altijd grijs, nooit rood/groen
            val_html = f'<span class="ct-val ct-dim">{n}</span>'

        return (
            f"<tr>"
            f'<td class="ct-label">{label}</td>'
            f"<td>{val_html}</td>"
            f"</tr>"
        )

    # Rijen gegroepeerd per betekenis:
    #   Groep 1: findings die actie vragen
    #   Groep 2: uitzonderingsstatus (informatief)
    #   Groep 3: scan-problemen
    #   Groep 4: positief resultaat
    rows_html = "".join([
        _row("Fail open",         item.fail_open,               "red"),
        _row("Accepted",          item.fail_accepted,            "green"),
        _row("Not applicable",    item.fail_not_applicable,      "green"),
        _row("Exc. not triggered",item.exception_not_triggered,  "dim"),
        _row("Not in profile",    item.not_in_profile,           "dim"),
        _row("Not executed",      item.not_executed,             "dim"),
        _row("Error",             item.error,                    "red"),
        _row("Unknown",           item.unknown,                  "red"),
        _row("Not checked",       item.notchecked,               "red"),
        _row("Pass",              item.pass_count,               "green"),
    ])

    return f'<table class="counts-table">{rows_html}</table>'


def _render_server_row_technical(item: ServerResult) -> str:
    """Rendert één tabelrij voor de technische serveroverzichtstabel.

    Kolommen (13 i.p.v. 19):
      Status | Server + OS + Profiel(tooltip) | Score | Telwaarden (grid) |
      Details | Scan leeftijd | Scan start | Bestanden
    """
    score_html   = _render_score_html(item.score_value, item.score)
    stale_badge  = badge("fresh", "OK") if not item.stale else badge("stale", "STALE")
    age_text     = f"{item.age_days}d" if item.age_days is not None else "n/a"
    html_link    = (
        div("muted", f"report: {esc(Path(item.html_path).name)}")
        if item.html_path
        else div("muted", "report: —")
    )
    xml_link     = div("muted", f"xml: {esc(Path(item.xml_path).name)}")
    findings_blk = build_findings_block(item)
    profile_tip  = _render_profile_tooltip(item.profile)
    counts_html  = _render_counts_grid(item)

    # Server + OS + Profiel samengevouwen in één cel
    server_cell = (
        f"<strong>{esc(item.server)}</strong>"
        f"{div('muted', esc(item.os_version))}"
        f"{profile_tip}"
    )

    return (
        f"<tr>"
        f"<td>{badge(status_class(item.status), item.status)}</td>"
        f"<td style='min-width:130px;'>{server_cell}</td>"
        f"<td class='num'>{score_html}</td>"
        f"<td style='min-width:200px;'>{counts_html}</td>"
        f"<td style='min-width:220px;'>{findings_blk}</td>"
        f"<td class='num'>{stale_badge}<br><span class='muted'>{age_text}</span></td>"
        f"<td class='num' style='white-space:nowrap;'>{format_datetime_nl(item.start_time)}</td>"
        f"<td style='min-width:140px;'>{html_link}{xml_link}</td>"
        f"</tr>"
    )


# ---------------------------------------------------------------------------
# Management-observaties
# ---------------------------------------------------------------------------

def management_observations(
    items: list[ServerResult],
    stale_days: int,
) -> list[str]:
    """
    Genereert managementobservaties op basis van de serverresultaten.
    Bevat: compliantie-percentage, open findings, high-severity top, OS-verdeling,
    stale scans en servers met de meeste open findings.
    """
    observations: list[str] = []
    total = len(items)

    # --- Compliantie-percentage ---
    compliant  = sum(1 for x in items if x.status == "COMPLIANT")
    low_risk   = sum(1 for x in items if x.status == "LOW RISK")
    acceptable = compliant + low_risk
    pct        = round(100 * acceptable / total) if total else 0
    observations.append(
        f"{pct}% van de servers ({acceptable}/{total}) voldoet volledig of met laag risico aan het profiel "
        f"({compliant} compliant, {low_risk} low risk)."
    )

    # --- Servers met scanfouten ---
    error_servers = [x.server for x in items if x.status == "ERROR"]
    if error_servers:
        observations.append(
            f"{len(error_servers)} server(s) hebben scanfouten en vragen technische opvolging: "
            f"{', '.join(sorted(error_servers))}."
        )

    # --- Totaal open findings en accepted ---
    open_fail_total = sum(x.fail_open for x in items)
    accepted_total  = sum(x.fail_accepted for x in items)
    if open_fail_total > 0:
        observations.append(
            f"Er zijn in totaal {open_fail_total} open findings verdeeld over de omgeving; "
            f"daarnaast zijn {accepted_total} findings bewust geaccepteerd met een uitzondering."
        )
    else:
        observations.append("Er zijn geen open findings in de omgeving.")

    # --- Meest voorkomende high-severity open finding ---
    high_counter: Counter = Counter()
    for item in items:
        for f in item.findings:
            if f.effective_status == "FAIL" and f.severity == "high":
                high_counter[f.title] += 1
    if high_counter:
        top_title, top_count = high_counter.most_common(1)[0]
        observations.append(
            f"Meest voorkomende open HIGH-finding: '{top_title}' — actief op {top_count} server(s)."
        )

    # --- OS-verdeling ---
    ol8 = sum(1 for x in items if x.os_version == "OL8")
    ol9 = sum(1 for x in items if x.os_version == "OL9")
    unk = sum(1 for x in items if x.os_version == "UNKNOWN")
    obs = f"Omgeving bevat {ol8} OL8-server(s) en {ol9} OL9-server(s)"
    obs += f" en {unk} server(s) met onbekende OS-versie." if unk else "."
    observations.append(obs)

    # --- Stale scans ---
    stale_servers = [x.server for x in items if x.stale]
    if stale_servers:
        observations.append(
            f"{len(stale_servers)} server(s) hebben een verouderde scan (ouder dan {stale_days} dagen): "
            f"{', '.join(sorted(stale_servers))}."
        )

    # --- Top 3 servers met meeste open findings ---
    top3 = sorted(items, key=lambda x: -x.fail_open)[:3]
    top3 = [x for x in top3 if x.fail_open > 0]
    if top3:
        top_str = ", ".join(f"{x.server} ({x.fail_open})" for x in top3)
        observations.append(
            f"Servers met de meeste open findings: {top_str}."
        )

    return observations


# ---------------------------------------------------------------------------
# Technisch HTML-rapport renderen
# ---------------------------------------------------------------------------

def render_technical_html(
    items: list[ServerResult],
    output_path: Path,
    base_dir: Path,
    stale_days: int,
    mapped_csv: str,
    manual_csv: str,
    manual_count: int,
    unmatched_rows: list[dict[str, str]],
    management_filename: str,
    low_risk_threshold: int,
) -> None:
    """Rendert het gedetailleerde technische HTML-rapport."""
    total_servers    = len(items)
    compliant        = sum(1 for x in items if x.status == "COMPLIANT")
    low_risk         = sum(1 for x in items if x.status == "LOW RISK")
    non_compliant    = sum(1 for x in items if x.status == "NON-COMPLIANT")
    error_count      = sum(1 for x in items if x.status == "ERROR")
    stale_count      = sum(1 for x in items if x.stale)

    total_fail_open  = sum(x.fail_open for x in items)
    total_accepted   = sum(x.fail_accepted for x in items)
    total_fail_na    = sum(x.fail_not_applicable for x in items)
    total_dormant    = sum(x.exception_not_triggered for x in items)
    total_not_in_prof= sum(x.not_in_profile for x in items)
    total_not_exec   = sum(x.not_executed for x in items)
    total_unknown    = sum(x.unknown for x in items)
    total_notchecked = sum(x.notchecked for x in items)

    ol8_count        = sum(1 for x in items if x.os_version == "OL8")
    ol9_count        = sum(1 for x in items if x.os_version == "OL9")
    unknown_os_count = sum(1 for x in items if x.os_version == "UNKNOWN")

    generated_at = datetime.now().strftime("%d-%m-%Y %H:%M")

    ordered = sorted(
        items,
        key=lambda x: (STATUS_SORT_ORDER.get(x.status, 9), 0 if x.stale else 1, -x.fail_open, x.server.lower()),
    )

    server_rows = "".join(_render_server_row_technical(item) for item in ordered)

    body = f"""
  <h1>OpenSCAP Technisch Overzicht</h1>
  <div class="small">Gegenereerd op: <strong>{generated_at}</strong></div>
  <div class="small">Basisdirectory: {esc(str(base_dir))}</div>
  <div class="small">Stale-drempel: {stale_days} dagen &nbsp;|&nbsp; Low-risk-drempel: ≤{low_risk_threshold} open findings</div>
  <div class="small">Exceptions CSV: {esc(mapped_csv)}</div>
  <div class="small">Manual mapping: {esc(manual_csv)} ({manual_count} regels)</div>
  <div class="small">Unmatched exceptions: {len(unmatched_rows)}</div>
  <div class="small" style="margin-top:6px;"><a href="{esc(management_filename)}">→ Ga naar managementoverzicht</a></div>

  <div class="legend">
    <strong>Legenda statussen</strong>
    <div class="legend-row">
      <span class="badge fail-open">FAIL OPEN</span>
      <span class="badge accepted">ACCEPTED</span>
      <span class="badge na">NOT APPLICABLE</span>
      <span class="badge dormant">EXCEPTION NOT TRIGGERED</span>
      <span class="badge not-in-profile">NOT IN PROFILE</span>
      <span class="badge not-executed">NOT EXECUTED</span>
      <span class="badge lowrisk">LOW RISK</span>
    </div>
    <div class="small" style="margin-top:8px;">
      <strong>FAIL OPEN</strong> = echte open finding zonder uitzondering. &nbsp;
      <strong>ACCEPTED</strong> = finding faalt maar heeft een bewust geregistreerde uitzondering. &nbsp;
      <strong>EXCEPTION NOT TRIGGERED</strong> = uitzondering bestaat maar de rule faalt momenteel niet. &nbsp;
      <strong>NOT IN PROFILE</strong> = uitzondering bestaat maar de rule zit niet in dit profiel. &nbsp;
      <strong>NOT EXECUTED</strong> = uitzondering bestaat maar de rule is niet zinvol uitgevoerd. &nbsp;
      <strong>LOW RISK</strong> = ≤{low_risk_threshold} open findings, geen ERROR/UNKNOWN/NOTCHECKED.
    </div>
  </div>

  <div class="grid">
    <div class="card"><div class="label">Servers totaal</div><div class="value">{total_servers}</div></div>
    <div class="card"><div class="label">OL8</div><div class="value">{ol8_count}</div></div>
    <div class="card"><div class="label">OL9</div><div class="value">{ol9_count}</div></div>
    <div class="card"><div class="label">OS onbekend</div><div class="value">{unknown_os_count}</div></div>
    <div class="card ok"><div class="label">Compliant</div><div class="value">{compliant}</div></div>
    <div class="card lowrisk"><div class="label">Low risk</div><div class="value">{low_risk}</div></div>
    <div class="card warn"><div class="label">Non-compliant</div><div class="value">{non_compliant}</div></div>
    <div class="card err"><div class="label">Error</div><div class="value">{error_count}</div></div>
    <div class="card"><div class="label">Stale scans</div><div class="value">{stale_count}</div></div>
    <div class="card fail"><div class="label">Open FAIL totaal</div><div class="value">{total_fail_open}</div></div>
    <div class="card accepted"><div class="label">Accepted totaal</div><div class="value">{total_accepted}</div></div>
    <div class="card na"><div class="label">Not Applicable totaal</div><div class="value">{total_fail_na}</div></div>
    <div class="card dormant"><div class="label">Exc. not triggered</div><div class="value">{total_dormant}</div></div>
    <div class="card notinprofile"><div class="label">Not in profile</div><div class="value">{total_not_in_prof}</div></div>
    <div class="card notexecuted"><div class="label">Not executed</div><div class="value">{total_not_exec}</div></div>
    <div class="card"><div class="label">UNKNOWN totaal</div><div class="value">{total_unknown}</div></div>
    <div class="card"><div class="label">NOTCHECKED totaal</div><div class="value">{total_notchecked}</div></div>
  </div>

  <h2>Top {TOP_OFFENDERS_N} meest voorkomende open findings</h2>
  {build_top_offenders(ordered)}

  <h2>Unmatched exceptions ({len(unmatched_rows)})</h2>
  {build_unmatched_block(unmatched_rows)}

  <h2>Servers ({total_servers})</h2>
  <div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Status</th>
        <th>Server / OS / Profiel</th>
        <th class="num">Score</th>
        <th>Telwaarden</th>
        <th>Details</th>
        <th class="num">Scan leeftijd</th>
        <th class="num">Scan start</th>
        <th>Bestanden</th>
      </tr>
    </thead>
    <tbody>
      {server_rows}
    </tbody>
  </table>
  </div>
"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        HTML_PAGE_TEMPLATE.format(
            title="OpenSCAP Technisch Overzicht",
            css=CSS_SHARED,
            body=body,
        ),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Management HTML-rapport renderen
# ---------------------------------------------------------------------------

def _render_server_row_management(item: ServerResult) -> str:
    """Rendert één tabelrij voor het managementoverzicht."""
    score_html = _render_score_html(item.score_value, item.score)

    if item.status == "ERROR":
        summary = "Scanfout aanwezig — eerst technische analyse nodig."
    elif item.fail_open == 0:
        summary = "Geen open findings."
    elif item.fail_open <= 10:
        summary = f"{item.fail_open} open finding(s) — beperkt; gerichte opvolging aanbevolen."
    elif item.fail_open <= DEFAULT_LOW_RISK_THRESHOLD:
        summary = f"{item.fail_open} open findings — meerdere; gerichte opvolging nodig."
    else:
        summary = f"{item.fail_open} open findings — aanzienlijk; structurele opvolging vereist."

    return (
        f"<tr>"
        f"<td><strong>{esc(item.server)}</strong></td>"
        f"<td>{esc(item.os_version)}</td>"
        f"<td>{badge(status_class(item.status), item.status)}</td>"
        f"<td>{score_html}</td>"
        f"<td>{item.fail_open}</td>"
        f"<td>{item.fail_accepted}</td>"
        f"<td>{item.error}</td>"
        f"<td>{esc(summary)}</td>"
        f"</tr>"
    )


def render_management_html(
    items: list[ServerResult],
    management_output_path: Path,
    technical_filename: str,
    base_dir: Path,
    mapped_csv: str,
    manual_csv: str,
    unmatched_rows: list[dict[str, str]],
    stale_days: int,
) -> None:
    """Rendert het management HTML-rapport met kernobservaties en serversamenvatting."""
    total_servers  = len(items)
    compliant      = sum(1 for x in items if x.status == "COMPLIANT")
    low_risk       = sum(1 for x in items if x.status == "LOW RISK")
    non_compliant  = sum(1 for x in items if x.status == "NON-COMPLIANT")
    error_count    = sum(1 for x in items if x.status == "ERROR")
    total_fail_open= sum(x.fail_open for x in items)
    total_accepted = sum(x.fail_accepted for x in items)
    total_not_in_p = sum(x.not_in_profile for x in items)

    generated_at = datetime.now().strftime("%d-%m-%Y %H:%M")

    ordered = sorted(
        items,
        key=lambda x: (STATUS_SORT_ORDER.get(x.status, 9), -x.fail_open, x.server.lower()),
    )

    observations_html = "".join(
        f"<li>{esc(obs)}</li>"
        for obs in management_observations(items, stale_days)
    )
    server_rows = "".join(_render_server_row_management(item) for item in ordered)

    body = f"""
  <h1>OpenSCAP Managementoverzicht</h1>
  <div class="small">Gegenereerd op: <strong>{generated_at}</strong></div>
  <div class="small">Basisdirectory: {esc(str(base_dir))}</div>
  <div class="small">Unmatched exceptions: {len(unmatched_rows)}</div>
  <div class="small" style="margin-top:6px;">
    <a href="{esc(technical_filename)}">→ Ga naar technisch detailrapport</a>
  </div>

  <div class="grid">
    <div class="card"><div class="label">Servers totaal</div><div class="value">{total_servers}</div></div>
    <div class="card ok"><div class="label">Compliant</div><div class="value">{compliant}</div></div>
    <div class="card lowrisk"><div class="label">Low risk</div><div class="value">{low_risk}</div></div>
    <div class="card warn"><div class="label">Non-compliant</div><div class="value">{non_compliant}</div></div>
    <div class="card err"><div class="label">Error</div><div class="value">{error_count}</div></div>
    <div class="card warn"><div class="label">Open findings</div><div class="value">{total_fail_open}</div></div>
    <div class="card accepted"><div class="label">Accepted</div><div class="value">{total_accepted}</div></div>
    <div class="card"><div class="label">Not in profile</div><div class="value">{total_not_in_p}</div></div>
  </div>

  <div class="panel">
    <h2>Kernobservaties</h2>
    <ul style="line-height: 1.8;">{observations_html}</ul>
  </div>

  <div class="panel">
    <h2>Samenvatting per server</h2>
    <table>
      <thead>
        <tr>
          <th>Server</th>
          <th>OS</th>
          <th>Status</th>
          <th>Score</th>
          <th>Open findings</th>
          <th>Accepted</th>
          <th>Error</th>
          <th>Samenvatting</th>
        </tr>
      </thead>
      <tbody>{server_rows}</tbody>
    </table>
  </div>

  <div class="small" style="margin-top: 16px;">
    Voor technische detailinformatie en rule-niveau analyse:
    <a href="{esc(technical_filename)}">open technisch detailrapport</a>.
  </div>
"""

    management_output_path.parent.mkdir(parents=True, exist_ok=True)
    management_output_path.write_text(
        HTML_PAGE_TEMPLATE.format(
            title="OpenSCAP Managementoverzicht",
            css=CSS_SHARED,
            body=body,
        ),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Hoofdfunctie
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(
        description="Genereert een technisch en management OpenSCAP HTML-rapport.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Voorbeeld:\n"
            "  python openscap_overall_report_v8.py \\\n"
            "      --base-dir  /scans \\\n"
            "      --mapped-csv /data/mapped_exceptions.csv \\\n"
            "      --manual-csv /data/manual_mapping.csv \\\n"
            "      --output    /reports/openscap_technical.html\n"
        ),
    )
    p.add_argument("--base-dir",          required=True,            help="Map met serverresultaten (*/<server>/*_latest_results.xml)")
    p.add_argument("--mapped-csv",        required=True,            help="Gemapt uitzonderingen-CSV (output van map_exceptions_to_oscap_v3.py)")
    p.add_argument("--manual-csv",        required=True,            help="Handmatige mapping-CSV")
    p.add_argument("--output",            required=True,            help="Pad naar technisch HTML-rapport")
    p.add_argument("--stale-days",        type=int,  default=8,     help="Aantal dagen waarna een scan als 'stale' beschouwd wordt (standaard: 8)")
    p.add_argument("--low-risk-threshold",type=int,  default=DEFAULT_LOW_RISK_THRESHOLD,
                                                                    help=f"Max open findings voor LOW RISK-status (standaard: {DEFAULT_LOW_RISK_THRESHOLD})")
    args = p.parse_args()

    base_dir   = Path(args.base_dir)
    mapped_csv = Path(args.mapped_csv)
    manual_csv = Path(args.manual_csv)
    output_path= Path(args.output)
    management_output_path = output_path.with_name("openscap_management.html")

    # --- Bestandscontrole ---
    errors = []
    if not base_dir.exists():
        errors.append(f"base-dir bestaat niet: {base_dir}")
    if not mapped_csv.exists():
        errors.append(f"mapped-csv bestaat niet: {mapped_csv}")
    if not manual_csv.exists():
        errors.append(f"manual-csv bestaat niet: {manual_csv}")
    if errors:
        for msg in errors:
            print(f"FOUT: {msg}", file=sys.stderr)
        return 1

    # --- Data laden ---
    exceptions_by_rule_id, unmatched_rows = load_exception_mapping(mapped_csv)
    manual_rows = read_csv_rows(manual_csv)

    xml_files = sorted(base_dir.glob("*/*_latest_results.xml"))
    if not xml_files:
        print(
            f"FOUT: geen *_latest_results.xml bestanden gevonden onder {base_dir}",
            file=sys.stderr,
        )
        return 2

    # --- XML-bestanden verwerken ---
    items = [
        parse_results_xml(
            xml_file,
            args.stale_days,
            exceptions_by_rule_id,
            args.low_risk_threshold,
        )
        for xml_file in xml_files
    ]

    # --- Rapporten renderen ---
    render_technical_html(
        items=items,
        output_path=output_path,
        base_dir=base_dir,
        stale_days=args.stale_days,
        mapped_csv=str(mapped_csv),
        manual_csv=str(manual_csv),
        manual_count=len(manual_rows),
        unmatched_rows=unmatched_rows,
        management_filename=management_output_path.name,
        low_risk_threshold=args.low_risk_threshold,
    )

    render_management_html(
        items=items,
        management_output_path=management_output_path,
        technical_filename=output_path.name,
        base_dir=base_dir,
        mapped_csv=str(mapped_csv),
        manual_csv=str(manual_csv),
        unmatched_rows=unmatched_rows,
        stale_days=args.stale_days,
    )

    # --- Samenvatting stdout ---
    total         = len(items)
    compliant     = sum(1 for x in items if x.status == "COMPLIANT")
    low_risk      = sum(1 for x in items if x.status == "LOW RISK")
    non_compliant = sum(1 for x in items if x.status == "NON-COMPLIANT")
    error_count   = sum(1 for x in items if x.status == "ERROR")
    total_open    = sum(x.fail_open for x in items)

    separator = "-" * 55
    print(separator)
    print(f"  Technisch rapport  : {output_path}")
    print(f"  Managementrapport  : {management_output_path}")
    print(separator)
    print(f"  Servers verwerkt   : {total}")
    print(f"    Compliant        : {compliant}")
    print(f"    Low risk         : {low_risk}")
    print(f"    Non-compliant    : {non_compliant}")
    print(f"    Error            : {error_count}")
    print(f"  Open findings      : {total_open}")
    print(f"  Exception rule_ids : {len(exceptions_by_rule_id)}")
    print(f"  Manual mappings    : {len(manual_rows)}")
    print(f"  Unmatched rows     : {len(unmatched_rows)}")
    print(separator)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
