#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import re
import sys
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path


@dataclass
class OscapRule:
    rule_id: str
    title: str


@dataclass
class ManualRuleMapping:
    rule_name: str
    matched_rule_id: str
    source_version: str = ""
    comment: str = ""


def normalize_text(value: str) -> str:
    value = value or ""
    value = unicodedata.normalize("NFKD", value)
    value = value.encode("ascii", "ignore").decode("ascii")
    value = value.lower().strip()
    value = re.sub(r"\bol[-_ ]?\d+\b", "", value)
    value = value.replace("&", " and ")
    value = re.sub(r"[^a-z0-9]+", " ", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def sniff_delimiter(sample: str) -> str:
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        return dialect.delimiter
    except Exception:
        if ";" in sample:
            return ";"
        if "\t" in sample:
            return "\t"
        return ","


def get_namespace(tag: str) -> str:
    if "}" in tag:
        return tag.split("}")[0] + "}"
    return ""


def parse_oscap_rules(xml_path: Path) -> list[OscapRule]:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns = get_namespace(root.tag)

    rules: list[OscapRule] = []
    for rule in root.findall(f".//{ns}Rule"):
        rule_id = rule.get("id", "").strip()
        title = rule.findtext(f"{ns}title", default="").strip()
        if rule_id and title:
            rules.append(OscapRule(rule_id=rule_id, title=title))

    return rules


def build_rule_index(
    rules: list[OscapRule],
) -> tuple[dict[str, OscapRule], list[tuple[str, OscapRule]], dict[str, OscapRule]]:
    exact_index: dict[str, OscapRule] = {}
    normalized_list: list[tuple[str, OscapRule]] = []
    rule_id_index: dict[str, OscapRule] = {}

    for rule in rules:
        norm = normalize_text(rule.title)
        if norm and norm not in exact_index:
            exact_index[norm] = rule
        normalized_list.append((norm, rule))
        rule_id_index[rule.rule_id] = rule

    return exact_index, normalized_list, rule_id_index


def read_exceptions_csv(csv_path: Path) -> list[dict[str, str]]:
    raw = csv_path.read_text(encoding="utf-8-sig", errors="replace")
    delimiter = sniff_delimiter(raw[:4096])
    lines = raw.splitlines()
    reader = csv.DictReader(lines, delimiter=delimiter)

    rows: list[dict[str, str]] = []
    for row in reader:
        cleaned: dict[str, str] = {}
        for k, v in row.items():
            key = (k or "").strip()
            if isinstance(v, list):
                value = " ".join(str(x).strip() for x in v if x is not None).strip()
            else:
                value = (v or "").strip()
            cleaned[key] = value
        rows.append(cleaned)

    return rows


def read_manual_rule_mapping(manual_csv: Path) -> dict[str, ManualRuleMapping]:
    rows = read_exceptions_csv(manual_csv)

    required = {"RULE_NAME", "MATCHED_RULE_ID"}
    present = set(rows[0].keys()) if rows else set()
    missing = required - present
    if missing:
        raise ValueError(f"verplichte kolommen ontbreken in manual csv: {sorted(missing)}")

    manual_index: dict[str, ManualRuleMapping] = {}
    for row in rows:
        rule_name = row.get("RULE_NAME", "").strip()
        matched_rule_id = row.get("MATCHED_RULE_ID", "").strip()
        if not rule_name or not matched_rule_id:
            continue

        norm = normalize_text(rule_name)
        manual_index[norm] = ManualRuleMapping(
            rule_name=rule_name,
            matched_rule_id=matched_rule_id,
            source_version=row.get("SOURCE_VERSION", "").strip(),
            comment=row.get("COMMENT", "").strip(),
        )

    return manual_index


def classify_reason(reason: str) -> str:
    r = (reason or "").lower()

    if "ipv6" in r or "virtuele server heeft geen usb" in r or "smartcards worden niet gebruikt" in r:
        return "NOT_APPLICABLE"
    if "ipa regelt dit" in r:
        return "ACCEPTED"
    if "wordt geregeld door oem" in r or "andere tool" in r or "aide wordt hiervoor gebruikt" in r:
        return "ACCEPTED"
    if "wordt (nog) niet gebruikt" in r:
        return "ACCEPTED"
    if "nodig voor ipa" in r:
        return "ACCEPTED"
    if "eigen niet dod tekst" in r or "eigen niet dod banner" in r:
        return "ACCEPTED"
    if "uitzoeken" in r:
        return "PENDING"

    return "ACCEPTED"


def match_rule(
    rule_name: str,
    exact_index: dict[str, OscapRule],
    normalized_list: list[tuple[str, OscapRule]],
    manual_index: dict[str, ManualRuleMapping],
    rule_id_index: dict[str, OscapRule],
    explicit_rule_id: str = "",
) -> tuple[str, str, str, str]:
    """
    Retourneert:
    (match_status, matched_rule_id, matched_title, match_comment)
    """

    explicit_rule_id = (explicit_rule_id or "").strip()
    if explicit_rule_id:
        mapped_rule = rule_id_index.get(explicit_rule_id)
        if mapped_rule:
            return "MATCHED_RULE_ID", mapped_rule.rule_id, mapped_rule.title, "direct rule_id match"
        return "MATCHED_RULE_ID_INVALID", explicit_rule_id, "", "rule_id niet gevonden in XML"

    norm_name = normalize_text(rule_name)

    if norm_name in exact_index:
        rule = exact_index[norm_name]
        return "MATCHED_EXACT", rule.rule_id, rule.title, ""

    manual = manual_index.get(norm_name)
    if manual:
        mapped_rule = rule_id_index.get(manual.matched_rule_id)
        if mapped_rule:
            return "MATCHED_MANUAL", mapped_rule.rule_id, mapped_rule.title, manual.comment
        return "MATCHED_MANUAL_INVALID_RULE_ID", manual.matched_rule_id, "", manual.comment

    candidates: list[OscapRule] = []
    for norm_title, rule in normalized_list:
        if norm_name and (norm_name in norm_title or norm_title in norm_name):
            candidates.append(rule)

    if len(candidates) == 1:
        return "MATCHED_PARTIAL", candidates[0].rule_id, candidates[0].title, ""

    rule_tokens = set(norm_name.split())
    best_rule = None
    best_score = 0.0

    for norm_title, rule in normalized_list:
        title_tokens = set(norm_title.split())
        if not rule_tokens or not title_tokens:
            continue

        overlap = len(rule_tokens & title_tokens)
        union = len(rule_tokens | title_tokens)
        score = overlap / union if union else 0.0

        if score > best_score and overlap >= 3 and score >= 0.45:
            best_score = score
            best_rule = rule

    if best_rule:
        return "MATCHED_FUZZY", best_rule.rule_id, best_rule.title, f"fuzzy_score={best_score:.2f}"

    return "NO_MATCH", "", "", ""


def main() -> int:
    parser = argparse.ArgumentParser(description="Koppel uitzonderingen uit CSV aan OpenSCAP rules.")
    parser.add_argument("--xml", required=True, help="Pad naar OpenSCAP results XML")
    parser.add_argument("--csv", required=True, help="Pad naar CSV met uitzonderingen")
    parser.add_argument("--manual-csv", required=True, help="Pad naar CSV met handmatige rule mappings")
    parser.add_argument("--out", required=True, help="Pad naar output CSV")
    args = parser.parse_args()

    xml_path = Path(args.xml)
    csv_path = Path(args.csv)
    manual_csv = Path(args.manual_csv)
    out_path = Path(args.out)

    if not xml_path.exists():
        print(f"FOUT: XML niet gevonden: {xml_path}", file=sys.stderr)
        return 1
    if not csv_path.exists():
        print(f"FOUT: CSV niet gevonden: {csv_path}", file=sys.stderr)
        return 2
    if not manual_csv.exists():
        print(f"FOUT: manual csv niet gevonden: {manual_csv}", file=sys.stderr)
        return 3

    rules = parse_oscap_rules(xml_path)
    if not rules:
        print("FOUT: geen OpenSCAP rules gevonden in XML", file=sys.stderr)
        return 4

    exact_index, normalized_list, rule_id_index = build_rule_index(rules)
    rows = read_exceptions_csv(csv_path)

    try:
        manual_index = read_manual_rule_mapping(manual_csv)
    except ValueError as exc:
        print(f"FOUT: {exc}", file=sys.stderr)
        return 5

    required_cols = {
        "SERVER",
        "ROOT_COMPLIANCE_NAME",
        "RULE_NAME",
        "TARGET_TYPE",
        "RULE_TYPE",
        "STATUS_NAME",
        "STATUS_CODE_NAME",
        "IS_CUSTOMIZED",
        "REASON",
    }
    present_cols = set(rows[0].keys()) if rows else set()
    missing = required_cols - present_cols
    if missing:
        print(f"FOUT: verplichte kolommen ontbreken: {sorted(missing)}", file=sys.stderr)
        return 6

    target_server = xml_path.parent.name.lower()

    out_rows = []
    for row in rows:
        source_server = row.get("SERVER", "").strip()
        rule_name = row.get("RULE_NAME", "").strip()
        explicit_rule_id = row.get("RULE_ID", "").strip()
        reason = row.get("REASON", "").strip()
        status_name = row.get("STATUS_NAME", "").strip().lower()
        forced_dashboard_status = row.get("FORCE_DASHBOARD_STATUS", "").strip()

        source_server_norm = source_server.lower()
        if source_server_norm in ("", "all"):
            source_scope = "ALL"
            include_row = True
            source_server_out = ""
        else:
            source_scope = "SERVER"
            include_row = source_server_norm == target_server
            source_server_out = source_server_norm

        if not include_row:
            continue

        match_status, matched_rule_id, matched_title, match_comment = match_rule(
            rule_name=rule_name,
            explicit_rule_id=explicit_rule_id,
            exact_index=exact_index,
            normalized_list=normalized_list,
            manual_index=manual_index,
            rule_id_index=rule_id_index,
        )

        if forced_dashboard_status:
            dashboard_status = forced_dashboard_status
        else:
            dashboard_status = classify_reason(reason) if status_name == "disabled" else "OPEN"

        out_rows.append({
            "SERVER": source_server,
            "SOURCE_SCOPE": source_scope,
            "SOURCE_SERVER": source_server_out,
            "RULE_ID": explicit_rule_id,
            "ROOT_COMPLIANCE_NAME": row.get("ROOT_COMPLIANCE_NAME", ""),
            "RULE_NAME": rule_name,
            "TARGET_TYPE": row.get("TARGET_TYPE", ""),
            "RULE_TYPE": row.get("RULE_TYPE", ""),
            "STATUS_NAME": row.get("STATUS_NAME", ""),
            "STATUS_CODE_NAME": row.get("STATUS_CODE_NAME", ""),
            "IS_CUSTOMIZED": row.get("IS_CUSTOMIZED", ""),
            "REASON": reason,
            "MATCH_STATUS": match_status,
            "MATCHED_RULE_ID": matched_rule_id,
            "MATCHED_OSCAP_TITLE": matched_title,
            "MATCH_COMMENT": match_comment,
            "SUGGESTED_DASHBOARD_STATUS": dashboard_status,
        })

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "SERVER",
                "SOURCE_SCOPE",
                "SOURCE_SERVER",
                "RULE_ID",
                "ROOT_COMPLIANCE_NAME",
                "RULE_NAME",
                "TARGET_TYPE",
                "RULE_TYPE",
                "STATUS_NAME",
                "STATUS_CODE_NAME",
                "IS_CUSTOMIZED",
                "REASON",
                "MATCH_STATUS",
                "MATCHED_RULE_ID",
                "MATCHED_OSCAP_TITLE",
                "MATCH_COMMENT",
                "SUGGESTED_DASHBOARD_STATUS",
            ],
        )
        writer.writeheader()
        writer.writerows(out_rows)

    matched = sum(
        1
        for r in out_rows
        if r["MATCH_STATUS"] not in ("NO_MATCH", "MATCHED_RULE_ID_INVALID", "MATCHED_MANUAL_INVALID_RULE_ID")
    )
    no_match = sum(
        1
        for r in out_rows
        if r["MATCH_STATUS"] in ("NO_MATCH", "MATCHED_RULE_ID_INVALID", "MATCHED_MANUAL_INVALID_RULE_ID")
    )
    matched_manual = sum(1 for r in out_rows if r["MATCH_STATUS"].startswith("MATCHED_MANUAL"))
    matched_rule_id = sum(1 for r in out_rows if r["MATCH_STATUS"] == "MATCHED_RULE_ID")

    print(f"Klaar: {out_path}")
    print(f"Target server: {target_server}")
    print(f"OpenSCAP rules gevonden: {len(rules)}")
    print(f"Exceptions geselecteerd: {len(out_rows)}")
    print(f"Manual mappings geladen: {len(manual_index)}")
    print(f"Matched: {matched}")
    print(f"Matched manual: {matched_manual}")
    print(f"Matched rule_id: {matched_rule_id}")
    print(f"No match: {no_match}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())