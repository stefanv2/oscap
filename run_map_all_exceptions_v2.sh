#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="${BASE_DIR:-/home/stefan/oscap/stig}"
CSV="${CSV:-/home/stefan/oscap/config/exceptions_stig.csv}"
MANUAL_CSV="${MANUAL_CSV:-/home/stefan/oscap/config/manual_rule_mapping.csv}"
MAP_SCRIPT="${MAP_SCRIPT:-/home/stefan/oscap/bin/map_exceptions_to_oscap_v2.py}"
TMP_DIR="${TMP_DIR:-/home/stefan/oscap/config/mapped_per_server}"
OUT_DIR="${OUT_DIR:-/home/stefan/oscap/config}"

mkdir -p "$TMP_DIR" "$OUT_DIR"
rm -f "$TMP_DIR"/exceptions_mapped_*.csv

echo "Start mapping van alle servers..."
echo "BASE_DIR   : $BASE_DIR"
echo "CSV        : $CSV"
echo "MANUAL_CSV : $MANUAL_CSV"
echo "MAP_SCRIPT : $MAP_SCRIPT"
echo

found=0

for xml in "$BASE_DIR"/*/*_latest_results.xml; do
  [ -e "$xml" ] || continue
  found=1

  server=$(basename "$(dirname "$xml")")
  xml_base=$(basename "$xml")

  profile=$(echo "$xml_base" | sed -E 's/^'"$server"'_(.+)_latest_results\.xml$/\1/')
  if [ -z "$profile" ] || [ "$profile" = "$xml_base" ]; then
    profile="unknown"
  fi

  out_file="$TMP_DIR/exceptions_mapped_${server}_${profile}.csv"

  echo "Processing server : $server"
  echo "Profile           : $profile"
  echo "XML               : $xml"
  echo "OUT               : $out_file"

  python3 "$MAP_SCRIPT" \
    --xml "$xml" \
    --csv "$CSV" \
    --manual-csv "$MANUAL_CSV" \
    --out "$out_file"

  echo
done

if [ "$found" -eq 0 ]; then
  echo "FOUT: geen *_latest_results.xml bestanden gevonden onder $BASE_DIR" >&2
  exit 1
fi

echo "Samenvoegen van per-server CSV bestanden per profiel..."
echo

profiles=$(find "$TMP_DIR" -maxdepth 1 -type f -name 'exceptions_mapped_*.csv' \
  | sed -E 's#^.*/exceptions_mapped_[^_]+_(.+)\.csv$#\1#' \
  | sort -u)

if [ -z "$profiles" ]; then
  echo "FOUT: geen per-server outputbestanden gevonden in $TMP_DIR" >&2
  exit 1
fi

for profile in $profiles; do
  tmp_merge="$OUT_DIR/exceptions_mapped_${profile}.csv.tmp"
  tmp_dedup="$OUT_DIR/exceptions_mapped_${profile}.csv.dedup"
  out_file="$OUT_DIR/exceptions_mapped_${profile}.csv"

  rm -f "$tmp_merge" "$tmp_dedup"

  first=1
  for f in "$TMP_DIR"/exceptions_mapped_*_"$profile".csv; do
    [ -e "$f" ] || continue

    if [ "$first" -eq 1 ]; then
      head -n 1 "$f" > "$tmp_merge"
      first=0
    fi

    tail -n +2 "$f" >> "$tmp_merge"
  done

  if [ ! -f "$tmp_merge" ]; then
    echo "Geen mergefile opgebouwd voor profiel: $profile"
    continue
  fi

  echo "Dedupliceren profiel: $profile"

  TMP_MERGE="$tmp_merge" TMP_DEDUP="$tmp_dedup" python3 - <<'PY'
import csv
import os
from pathlib import Path

tmp_merge = Path(os.environ["TMP_MERGE"])
tmp_dedup = Path(os.environ["TMP_DEDUP"])

with tmp_merge.open("r", encoding="utf-8", newline="") as f:
    reader = csv.DictReader(f)
    fieldnames = reader.fieldnames
    rows = list(reader)

if not fieldnames:
    raise SystemExit("Geen header gevonden in tijdelijke mergefile.")

seen = set()
deduped = []

for row in rows:
    key = (
        row.get("SERVER", ""),
        row.get("SOURCE_SCOPE", ""),
        row.get("SOURCE_SERVER", ""),
        row.get("RULE_ID", ""),
        row.get("MATCHED_RULE_ID", ""),
        row.get("SUGGESTED_DASHBOARD_STATUS", ""),
    )
    if key in seen:
        continue
    seen.add(key)
    deduped.append(row)

with tmp_dedup.open("w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(deduped)

print(f"Originele regels : {len(rows)}")
print(f"Unieke regels    : {len(deduped)}")
PY

  mv "$tmp_dedup" "$out_file"
  rm -f "$tmp_merge"

  echo "Klaar profiel: $profile"
  echo "Output       : $out_file"
  echo
done

echo "Alles klaar."
echo "Beschikbare outputs:"
ls -1 "$OUT_DIR"/exceptions_mapped_*.csv 2>/dev/null || true
