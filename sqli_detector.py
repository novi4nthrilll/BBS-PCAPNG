#!/usr/bin/env python3
"""
Boolean-Based Blind SQLi Detector & Data Reconstructor
=====================================================
Fokus HANYA pada boolean-based blind SQL injection.

Cara kerja:
1. Auto-detect port HTTP di PCAPNG
2. Extract semua request/response sekaligus (bulk, cepat)
3. Identifikasi boolean pattern (TRUE vs FALSE dari response size)
4. Parse setiap payload: posisi karakter + karakter yang dites
5. Reconstruct data yang berhasil di-extract attacker

Hanya butuh ~3-4x tshark call, bukan ribuan.
"""

import subprocess
import sys
import os
import re
import json
import shutil
from collections import defaultdict, Counter
from urllib.parse import unquote, unquote_plus, urlparse

# ─── Colors ─────────────────────────────────────────────────────────────────

class C:
    CY = '\033[96m'; G = '\033[92m'; Y = '\033[93m'; R = '\033[91m'
    E = '\033[0m'; BO = '\033[1m'; D = '\033[2m'

FLAG_PAT = re.compile(r'(?:LKS|FGTE|picoCTF|flag|FLAG|CTF)\{[^}]+\}')


# ─── Shell helper ───────────────────────────────────────────────────────────

def run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except:
        return ""


def check_deps():
    """Validate required tools are installed."""
    if not shutil.which("tshark"):
        print(f"{C.R}[!] tshark not found. Install: sudo apt install tshark{C.E}")
        sys.exit(1)
    if not shutil.which("strings"):
        print(f"{C.Y}[!] 'strings' not found. Install: sudo apt install binutils{C.E}")


def tshark(pcap, args, ports=None, timeout=60):
    d = " ".join(f"-d tcp.port={p},http" for p in (ports or []))
    return run(f"tshark -r '{pcap}' {d} {args} 2>/dev/null", timeout)


def decode(s):
    """Triple URL-decode: unquote_plus handles + as space, then unquote for %XX."""
    if not s:
        return s
    try:
        return unquote(unquote(unquote_plus(s)))
    except:
        return s


def find_flags(text):
    return FLAG_PAT.findall(text or "")


# ─── Step 1: Detect HTTP port ──────────────────────────────────────────────

def find_http_port(pcap):
    """Find HTTP server port using dstport frequency analysis (supports 1-65535)."""
    # Extract ONLY dstport (where traffic is going TO)
    out = tshark(pcap, '-Y "tcp" -T fields -e tcp.dstport -E separator="|"')
    if not out.strip():
        return None

    # Count how often each port appears as destination
    dst_counts = Counter()
    for line in out.strip().split('\n'):
        for p in line.split('|'):
            p = p.strip()
            if p.isdigit():
                dst_counts[int(p)] += 1

    # Server ports have high dstport frequency (many requests go TO them)
    # Ephemeral client ports have low frequency (1-2 connections each)
    # Filter: must appear at least 5 times as dstport to be a server candidate
    min_hits = 5
    candidates = [(port, cnt) for port, cnt in dst_counts.items()
                  if cnt >= min_hits and 1 <= port <= 65535]
    # Sort by frequency descending (most hit = most likely server)
    candidates.sort(key=lambda x: -x[1])

    # Test top candidates for HTTP traffic
    for port, _ in candidates[:12]:
        test = tshark(pcap,
            f'-d tcp.port={port},http -Y "http.request" -T fields -e frame.number',
            timeout=30)
        if test.strip():
            return port
    return None


# ─── Step 2: Bulk extract all HTTP data ─────────────────────────────────────

def bulk_extract(pcap, port):
    """
    Extract ALL request+response data in 2 tshark calls.
    Returns list of dicts: {frame, method, uri, resp_status, resp_size}
    """
    # Call 1: All requests
    req_out = tshark(pcap,
        '-Y "http.request" -T fields '
        '-e frame.number -e http.request.method -e http.host '
        '-e http.request.uri -e http.request.full_uri '
        '-E separator="|" -E quote=n',
        ports=[port])

    # Call 2: All responses matched to requests
    resp_out = tshark(pcap,
        '-Y "http.response" -T fields '
        '-e frame.number -e http.response.code '
        '-e http.content_length -e http.request_in '
        '-E separator="|" -E quote=n',
        ports=[port])

    # Build request map
    reqs = {}
    for line in (req_out or "").strip().split('\n'):
        p = line.split('|')
        if len(p) < 4:
            continue
        frame = p[0].strip()
        reqs[frame] = {
            "frame": frame,
            "method": p[1].strip(),
            "host": p[2].strip(),
            "uri": p[3].strip(),
            "full_uri": p[4].strip() if len(p) > 4 else "",
            "resp_status": "",
            "resp_size": 0,
            "resp_frame": "",
        }

    # Match responses
    for line in (resp_out or "").strip().split('\n'):
        p = line.split('|')
        if len(p) < 4:
            continue
        resp_frame, status, clen, req_in = p[0].strip(), p[1].strip(), p[2].strip(), p[3].strip()
        if req_in in reqs:
            reqs[req_in]["resp_frame"] = resp_frame
            reqs[req_in]["resp_status"] = status
            try:
                reqs[req_in]["resp_size"] = int(clen) if clen else 0
            except ValueError:
                reqs[req_in]["resp_size"] = 0

    return list(reqs.values())


# ─── Step 3: Response body classification ────────────────────────────────────

def decode_hex_body(raw):
    """Decode hex-encoded tshark output to string."""
    raw = raw.strip()
    if raw and all(c in '0123456789abcdefABCDEF|' for c in raw):
        try:
            return bytes.fromhex(raw.replace('|', '')).decode('utf-8', errors='ignore')
        except:
            pass
    return raw


def is_true_response(body):
    """
    Parse response body to determine if it's a TRUE boolean result.
    Tries JSON parsing first, falls back to string matching.
    """
    if not body:
        return None
    # Try JSON parse
    try:
        data = json.loads(body.strip())
        if isinstance(data, dict):
            # Check for common boolean keys
            for key in ('available', 'exists', 'found', 'result', 'match', 'success'):
                if key in data:
                    return data[key] is True or data[key] == True
            # Check any boolean value in dict
            for v in data.values():
                if isinstance(v, bool):
                    return v
    except (json.JSONDecodeError, ValueError):
        pass
    # Fallback: string matching
    bl = body.lower().strip()
    if bl in ('true', '1', 'yes'):
        return True
    if bl in ('false', '0', 'no'):
        return False
    if '"true"' in bl or ':true' in bl.replace(' ', ''):
        return True
    if '"false"' in bl or ':false' in bl.replace(' ', ''):
        return False
    return None


def classify_responses(pcap, port, reqs, sample_count=20):
    """
    Classify each request as TRUE or FALSE.
    Hybrid strategy:
      1. Try semantic parsing (JSON bool keys, true/false strings)
      2. If too many unknowns, fall back to frequency analysis
         (minority response = TRUE, since fewer chars match than don't)
    Returns (true_reqs, false_reqs, unknown_reqs, info_dict).
    """
    # Collect unique response sizes and sample frames for each
    size_to_frames = defaultdict(list)
    for r in reqs:
        if r["resp_frame"]:
            size_to_frames[r["resp_size"]].append(r["resp_frame"])

    # Phase 1: Try semantic parsing for each unique size
    size_is_true = {}   # size -> True/False/None
    size_body_sample = {}  # size -> body text
    size_count = {}  # size -> how many reqs have this size

    for size, frames in size_to_frames.items():
        size_count[size] = len(frames)
        sampled = 0
        for f in frames:
            if sampled >= sample_count:
                break
            raw = tshark(pcap,
                f'-Y "frame.number == {f}" -T fields -e http.file_data -E separator="|" -E quote=n',
                ports=[port], timeout=15)
            body = decode_hex_body(raw)
            result = is_true_response(body)
            if result is not None:
                size_is_true[size] = result
                size_body_sample[size] = body.strip()
                break
            sampled += 1

    # Phase 2: If semantic parsing couldn't classify all sizes, use frequency
    classified_sizes = {sz for sz, v in size_is_true.items() if v is not None}
    unclassified_sizes = set(size_to_frames.keys()) - classified_sizes

    if unclassified_sizes and len(size_to_frames) >= 2:
        # Frequency analysis: the MINORITY response = TRUE
        # (attacker guesses wrong more often than right)
        unclassified_with_counts = [(sz, size_count.get(sz, 0)) for sz in unclassified_sizes]
        unclassified_with_counts.sort(key=lambda x: x[1])  # sort by count ascending

        if len(unclassified_with_counts) == 2:
            minority_sz = unclassified_with_counts[0][0]  # fewer occurrences = TRUE
            majority_sz = unclassified_with_counts[1][0]
            size_is_true[minority_sz] = True
            size_is_true[majority_sz] = False
            # Grab a sample body for display
            for label, sz in [("TRUE", minority_sz), ("FALSE", majority_sz)]:
                if sz not in size_body_sample:
                    frames = size_to_frames[sz]
                    if frames:
                        raw = tshark(pcap,
                            f'-Y "frame.number == {frames[0]}" -T fields -e http.file_data -E separator="|" -E quote=n',
                            ports=[port], timeout=15)
                        size_body_sample[sz] = decode_hex_body(raw).strip()
        elif len(unclassified_with_counts) > 2:
            # More than 2 unique sizes among unclassified — try grouping
            # by similarity. Take the rarest as TRUE, rest as FALSE
            rarest = unclassified_with_counts[0][0]
            size_is_true[rarest] = True
            for sz, _ in unclassified_with_counts[1:]:
                size_is_true[sz] = False

    # Apply classification to all requests
    true_reqs = []
    false_reqs = []
    unknown_reqs = []
    for r in reqs:
        sz = r["resp_size"]
        if sz in size_is_true and size_is_true[sz] is not None:
            if size_is_true[sz]:
                true_reqs.append(r)
            else:
                false_reqs.append(r)
        else:
            unknown_reqs.append(r)

    return true_reqs, false_reqs, unknown_reqs, size_is_true, size_body_sample


# ─── Step 4: Parse boolean blind payloads ──────────────────────────────────

# === Regex patterns ===

# Pattern A: Direct column — substr(col, pos, 1) or substr(alias.col, pos, 1)
RE_SUBSTR_DIRECT = re.compile(
    r'(?:substr(?:ing)?|mid)\s*\(\s*(?:\w+\.)?(\w+)\s*,\s*(\d+)\s*,\s*1\s*\)',
    re.IGNORECASE
)

# Pattern B: Nested subquery — substr((SELECT col FROM tbl ...), pos, 1)
RE_SUBSTR_NESTED = re.compile(
    r'(?:substr(?:ing)?|mid)\s*\(\s*\(\s*SELECT\s+(?:\w+\.)?(\w+)\s+FROM\s+(\w+)'
    r'(.*?)\)\s*,\s*(\d+)\s*,\s*1\s*\)',
    re.IGNORECASE | re.DOTALL
)

# Character comparison: )='CHAR' followed by comment markers (--, --+, #, /*) or end
RE_CHAR_EQ = re.compile(r"\)\s*=\s*'(.+?)'(?:\s*(?:--+|#|/\*|--)|\s*$)", re.IGNORECASE)
RE_CHAR_EQ2 = re.compile(r"=\s*'([^']+)'(?:\s*(?:--+|#|/\*|--)|\s*$)", re.IGNORECASE)

RE_FROM_TABLE = re.compile(r'FROM\s+(\w+)', re.IGNORECASE)
RE_OFFSET = re.compile(r'OFFSET\s+(\d+)', re.IGNORECASE)
RE_LIMIT = re.compile(r'LIMIT\s+(\d+)', re.IGNORECASE)
RE_WHERE = re.compile(r"WHERE\s+(.+?)(?:\s+ORDER|\s+LIMIT|\s+GROUP|\)\s*=)", re.IGNORECASE)

# Detect boolean blind SQLi: substr/mid + character comparison
RE_BLIND_SQLI = re.compile(
    r'(?:substr(?:ing)?|mid)\s*\(.+?\)\s*=\s*\'.\'\s*(?:--+|#|/\*|--|\s*$)',
    re.IGNORECASE
)


# Pattern C: Binary search — unicode(substr((SELECT col FROM ...), pos, 1)) >= N
RE_BINARY_SEARCH = re.compile(
    r'(?:unicode|ascii|ord)\s*\(\s*(?:substr(?:ing)?|mid)\s*\('
    r'\s*\(\s*SELECT\s+(?:\w+\.)?(\w+)\s+FROM\s+(\w+)'
    r'([^)]*(?:\([^)]*\))*[^)]*)\)\s*,\s*(\d+)\s*,\s*1\s*\)\s*\)\s*\)'
    r'\s*>=\s*(\d+)',
    re.IGNORECASE | re.DOTALL
)

# Pattern C2: Binary search direct — unicode(substr(col, pos, 1)) >= N
RE_BINARY_DIRECT = re.compile(
    r'(?:unicode|ascii|ord)\s*\(\s*(?:substr(?:ing)?|mid)\s*\('
    r'\s*(?:\w+\.)?(\w+)\s*,\s*(\d+)\s*,\s*1\s*\)\s*\)'
    r'\s*>=\s*(\d+)',
    re.IGNORECASE
)

# Pattern D: Length enumeration — length((SELECT col FROM ...))=N
RE_LENGTH_ENUM = re.compile(
    r'length\s*\(\s*\(\s*SELECT\s+(?:\w+\.)?(\w+)\s+FROM\s+(\w+)'
    r'(.*?)\)\s*\)\s*=\s*(\d+)',
    re.IGNORECASE | re.DOTALL
)

# Detect any boolean blind SQLi (char compare OR binary search OR length enum)
RE_ANY_BLIND = re.compile(
    r'(?:'
    r'(?:substr(?:ing)?|mid)\s*\(.+?\)\s*=\s*\'.\'\s*(?:--+|#|/\*|--|\s*$)'
    r'|'
    r'(?:unicode|ascii|ord)\s*\(\s*(?:substr(?:ing)?|mid)\s*\(.+?\)\s*>=\s*\d+'
    r'|'
    r'length\s*\(.+?\)\s*=\s*\d+'
    r')',
    re.IGNORECASE
)


def get_extraction_context(uri):
    """Determine context: schema, schema_columns, or table name."""
    low = uri.lower()
    if 'sqlite_master' in low:
        return 'schema'
    if 'pragma_table_info' in low:
        return 'schema_columns'
    if 'information_schema' in low:
        return 'schema'
    m = RE_FROM_TABLE.search(uri)
    return m.group(1) if m else 'unknown'


def get_where_context(uri):
    """Extract WHERE clause, cleaned of payload artifacts."""
    m = RE_WHERE.search(uri)
    if not m:
        return ""
    clause = m.group(1).strip()
    clause = re.sub(r'\s*--\+?.*$', '', clause)
    clause = re.sub(r"\s*'\s*$", '', clause)
    return clause


def parse_blind_payload(url_decoded):
    """
    Parse a boolean-blind SQLi URL. Supports 3 techniques:
      1. char_compare:  substr(col,pos,1)='c' --  (direct or nested)
      2. binary_search: unicode(substr(col,pos,1))>=N  (binary search on ASCII)
      3. length_enum:   length(col)=N  (string length enumeration)
    Returns dict or None.
    """
    info = {}

    # ── Try binary search: unicode(substr((SELECT col FROM tbl ...), pos, 1)) >= N ──
    m = RE_BINARY_SEARCH.search(url_decoded)
    if m:
        info["type"] = "binary_search"
        info["column"] = m.group(1)
        info["table"] = m.group(2)
        info["position"] = int(m.group(4))
        info["threshold"] = int(m.group(5))
        sub_body = m.group(3)
        off_m = RE_OFFSET.search(sub_body)
        info["offset"] = int(off_m.group(1)) if off_m else 0
        info["where"] = get_where_context(sub_body) if 'WHERE' in sub_body.upper() else ""
        info["context"] = get_extraction_context(url_decoded)
        return info

    # ── Try binary search direct: unicode(substr(col, pos, 1)) >= N ──
    m = RE_BINARY_DIRECT.search(url_decoded)
    if m:
        info["type"] = "binary_search"
        info["column"] = m.group(1)
        info["position"] = int(m.group(2))
        info["threshold"] = int(m.group(3))
        fm = RE_FROM_TABLE.search(url_decoded)
        info["table"] = fm.group(1) if fm else "?"
        om = RE_OFFSET.search(url_decoded)
        info["offset"] = int(om.group(1)) if om else 0
        info["where"] = get_where_context(url_decoded)
        info["context"] = get_extraction_context(url_decoded)
        return info

    # ── Try length enumeration: length((SELECT col FROM tbl ...))=N ──
    m = RE_LENGTH_ENUM.search(url_decoded)
    if m:
        info["type"] = "length_enum"
        info["column"] = m.group(1)
        info["table"] = m.group(2)
        info["length_guess"] = int(m.group(4))
        sub_body = m.group(3)
        off_m = RE_OFFSET.search(sub_body)
        info["offset"] = int(off_m.group(1)) if off_m else 0
        info["where"] = get_where_context(sub_body) if 'WHERE' in sub_body.upper() else ""
        info["context"] = get_extraction_context(url_decoded)
        info["position"] = 0  # not applicable
        return info

    # ── Try nested subquery: substr((SELECT col FROM tbl ...), pos, 1) = 'c' ──
    m = RE_SUBSTR_NESTED.search(url_decoded)
    if m:
        info["type"] = "char_compare"
        info["column"] = m.group(1)
        info["table"] = m.group(2)
        info["position"] = int(m.group(4))
        sub_body = m.group(3)
        off_m = RE_OFFSET.search(sub_body)
        info["offset"] = int(off_m.group(1)) if off_m else 0
        info["where"] = get_where_context(sub_body) if 'WHERE' in sub_body.upper() else ""
        info["context"] = get_extraction_context(url_decoded)
        cm = RE_CHAR_EQ.search(url_decoded) or RE_CHAR_EQ2.search(url_decoded)
        if not cm:
            return None
        info["char"] = cm.group(1)
        return info

    # ── Try direct column: substr(col, pos, 1) = 'c' ──
    m = RE_SUBSTR_DIRECT.search(url_decoded)
    if m:
        info["type"] = "char_compare"
        info["column"] = m.group(1)
        info["position"] = int(m.group(2))
        fm = RE_FROM_TABLE.search(url_decoded)
        info["table"] = fm.group(1) if fm else "?"
        om = RE_OFFSET.search(url_decoded)
        info["offset"] = int(om.group(1)) if om else 0
        info["where"] = get_where_context(url_decoded)
        info["context"] = get_extraction_context(url_decoded)
        cm = RE_CHAR_EQ.search(url_decoded) or RE_CHAR_EQ2.search(url_decoded)
        if not cm:
            return None
        info["char"] = cm.group(1)
        return info

    return None


# ─── Step 5: Reconstruct extracted data ─────────────────────────────────────

def reconstruct_data(extraction_entries):
    """
    Given list of {position, char, is_true, offset, column, table},
    reconstruct the data character by character.
    Groups by (offset, column, table) to handle multiple extractions.
    """
    # Group by extraction target
    groups = defaultdict(dict)  # (offset, col, table) -> {position: char}

    for entry in extraction_entries:
        if not entry.get("is_true"):
            continue
        key = (entry.get("offset", 0), entry.get("column", "?"), entry.get("table", "?"))
        pos = entry["position"]
        char = entry["char"]
        # Only store if we haven't found this position yet
        if pos not in groups[key]:
            groups[key][pos] = char

    results = {}
    for key, pos_map in groups.items():
        if not pos_map:
            continue
        offset, col, table = key
        max_pos = max(pos_map.keys())
        chars = []
        for i in range(1, max_pos + 1):
            chars.append(pos_map.get(i, '?'))
        results[key] = ''.join(chars)

    return results

def reconstruct_binary_search(entries):
    """
    Reconstruct data from binary search (unicode >= N) queries.
    For each position: the highest TRUE threshold = the actual ASCII value.
    """
    # Group by position
    pos_data = defaultdict(list)  # position -> [(threshold, is_true), ...]
    for e in entries:
        if e.get("type") != "binary_search":
            continue
        pos_data[e["position"]].append((e["threshold"], e["is_true"]))

    result = {}
    for pos, tests in pos_data.items():
        # Find highest threshold where is_true=True
        true_thresholds = [t for t, is_t in tests if is_t]
        if true_thresholds:
            ascii_val = max(true_thresholds)
            result[pos] = chr(ascii_val)

    return result


def get_string_lengths(entries):
    """Extract confirmed string lengths from length_enum queries."""
    lengths = {}
    for e in entries:
        if e.get("type") == "length_enum" and e.get("is_true"):
            key = (e.get("offset", 0), e.get("column", "?"), e.get("table", "?"))
            lengths[key] = e["length_guess"]
    return lengths




# ─── Main Analysis ──────────────────────────────────────────────────────────

def analyze(pcap):
    """Full boolean-based blind SQLi analysis."""

    # ── Detect port ──
    print(f"{C.CY}[*] Scanning for HTTP port...{C.E}", end=" ")
    port = find_http_port(pcap)
    if not port:
        print(f"\n{C.R}[!] No HTTP traffic found.{C.E}")
        return
    print(f"{C.G}{port}{C.E}")

    # ── Bulk extract ──
    print(f"{C.CY}[*] Extracting HTTP traffic (bulk)...{C.E}", end=" ")
    all_reqs = bulk_extract(pcap, port)
    print(f"{C.G}{len(all_reqs)} requests{C.E}")

    if not all_reqs:
        print(f"{C.R}[!] No HTTP requests found.{C.E}")
        return

    # ── Find boolean blind payloads ──
    print(f"{C.CY}[*] Scanning for boolean-based blind SQLi...{C.E}")

    blind_reqs = []
    for req in all_reqs:
        raw_uri = req.get("full_uri") or req["uri"]
        decoded_uri = decode(raw_uri)
        parsed = parse_blind_payload(decoded_uri)
        if parsed:
            req["blind"] = parsed
            req["decoded_uri"] = decoded_uri
            blind_reqs.append(req)

    if not blind_reqs:
        print(f"{C.Y}[!] No boolean-based blind SQLi detected.{C.E}")
        print(f"{C.D}    Tool ini hanya mendeteksi boolean-based blind SQLi.{C.E}")
        print(f"{C.D}    Pattern: substr(col,pos,1)='char' + TRUE/FALSE response{C.E}")
        return

    # ── Group by endpoint ──
    groups = defaultdict(list)
    for req in blind_reqs:
        path = urlparse(req.get("full_uri") or req["uri"]).path
        groups[path].append(req)

    all_true_frames = set()
    all_false_frames = set()
    all_classified_reqs = []  # (req, is_true) for export

    for endpoint, reqs in groups.items():
        print(f"\n{C.BO}{'═'*65}")
        print(f"  BOOLEAN-BASED BLIND SQLi DETECTED")
        print(f"{'═'*65}{C.E}\n")

        host = reqs[0].get("host", "?")
        print(f"  {C.R}Target  : {host}{endpoint}{C.E}")
        print(f"  {C.R}Payloads: {len(reqs)} blind requests{C.E}")

        # Show sample payload
        sample = reqs[0].get("decoded_uri", "")
        print(f"\n  {C.D}Sample payload:{C.E}")
        print(f"  {C.D}{sample[:150]}{C.E}")

        # ── Classify responses via JSON body parsing ──
        print(f"\n{C.BO}  ┌─ Response Analysis ─────────────────────────────────┐{C.E}")

        size_dist = defaultdict(int)
        for r in reqs:
            size_dist[r["resp_size"]] += 1

        print(f"  {C.CY}  Response size distribution:{C.E}")
        for sz, cnt in sorted(size_dist.items()):
            pct = cnt / len(reqs) * 100
            print(f"    {sz:>4}B  →  {cnt:>5} responses ({pct:.1f}%)")

        # Classify via hybrid approach (semantic + frequency fallback)
        true_reqs, false_reqs, unknown_reqs, size_is_true, size_body_sample = \
            classify_responses(pcap, port, reqs, sample_count=20)

        # Determine which method was used
        has_semantic = any(
            'true' in (size_body_sample.get(sz, '') or '').lower() or
            'false' in (size_body_sample.get(sz, '') or '').lower()
            for sz in size_is_true
        )
        method = "semantic (JSON/string)" if has_semantic else "frequency analysis (minority=TRUE)"
        print(f"\n  {C.D}  Classification method: {method}{C.E}")

        for sz, is_true in size_is_true.items():
            label = "TRUE" if is_true else "FALSE"
            body_sample = size_body_sample.get(sz, "?")[:60]
            color = C.G if is_true else C.R
            print(f"\n  {color}  {label:>5} ({sz:>3}B): \"{body_sample}\"{C.E}")

        if unknown_reqs:
            print(f"\n  {C.Y}  [!] {len(unknown_reqs)} responses could not be classified{C.E}")

        print(f"\n  {C.G}  TRUE  responses : {len(true_reqs)} (character match!){C.E}")
        print(f"  {C.R}  FALSE responses : {len(false_reqs)} (no match){C.E}")
        if unknown_reqs:
            print(f"  {C.Y}  UNKNOWN         : {len(unknown_reqs)}{C.E}")
        print(f"{C.BO}  └{'─'*55}┘{C.E}")

        # ── Build entries ──
        print(f"\n{C.BO}  ┌─ Data Extraction ───────────────────────────────────┐{C.E}")

        # Mark each request with its is_true status
        true_frames = {r["frame"] for r in true_reqs}
        false_frames_ep = {r["frame"] for r in false_reqs}
        all_true_frames.update(true_frames)
        all_false_frames.update(false_frames_ep)
        entries = []
        for req in reqs:
            info = req["blind"]
            is_true = req["frame"] in true_frames
            all_classified_reqs.append((req, is_true))
            entry = {
                "type": info.get("type", "char_compare"),
                "position": info.get("position", 0),
                "is_true": is_true,
                "column": info.get("column", "?"),
                "table": info.get("table", "?"),
                "offset": info.get("offset", 0),
                "where": info.get("where", ""),
                "context": info.get("context", ""),
            }
            # Type-specific fields
            if entry["type"] == "char_compare":
                entry["char"] = info.get("char", "?")
            elif entry["type"] == "binary_search":
                entry["threshold"] = info.get("threshold", 0)
            elif entry["type"] == "length_enum":
                entry["length_guess"] = info.get("length_guess", 0)
            entries.append(entry)

        # Group by (column, table, where) — multi-row grouping
        table_groups = defaultdict(list)
        for e in entries:
            key = (e["column"], e["table"], e["where"])
            table_groups[key].append(e)

        all_targets = {}
        for (column, table, where), group_entries in table_groups.items():
            where_short = where[:50] if where else "N/A"
            ctx = group_entries[0].get("context", "")
            ctx_label = f" [{ctx}]" if ctx else ""

            # Determine types in this group
            types = set(e["type"] for e in group_entries)
            type_label = ", ".join(types)

            print(f"\n  {C.CY}  ┌─ {table}.{column}{ctx_label} ({type_label}){C.E}")
            print(f"  {C.D}  │  WHERE: {where_short}{C.E}")

            # Sub-group by offset
            offset_groups = defaultdict(list)
            for e in group_entries:
                offset_groups[e["offset"]].append(e)

            # Get string lengths from length_enum (if available)
            string_lengths = get_string_lengths(group_entries)

            reconstructed_rows = {}
            for offset in sorted(offset_groups.keys()):
                off_entries = offset_groups[offset]
                off_key = (offset, column, table)
                n_tests = len(off_entries)
                n_true = sum(1 for e in off_entries if e["is_true"])

                # Separate by type
                char_entries = [e for e in off_entries if e["type"] == "char_compare"]
                bin_entries = [e for e in off_entries if e["type"] == "binary_search"]
                len_entries = [e for e in off_entries if e["type"] == "length_enum"]

                data = ""
                # Method 1: char_compare reconstruction
                if char_entries:
                    result = reconstruct_data(char_entries)
                    for key, d in result.items():
                        data = d

                # Method 2: binary search reconstruction
                if bin_entries:
                    bs_result = reconstruct_binary_search(bin_entries)
                    if bs_result:
                        max_pos = max(bs_result.keys())
                        chars = []
                        for i in range(1, max_pos + 1):
                            chars.append(bs_result.get(i, '?'))
                        data = ''.join(chars)

                if data:
                    reconstructed_rows[offset] = data

                # Show detail line
                if bin_entries:
                    # Show binary search detail
                    pos_details = defaultdict(list)
                    for e in bin_entries:
                        pos_details[e["position"]].append((e["threshold"], e["is_true"]))
                    pos_summary = []
                    for pos in sorted(pos_details.keys()):
                        tests = pos_details[pos]
                        true_vals = [t for t, ok in tests if ok]
                        if true_vals:
                            ch = chr(max(true_vals))
                            pos_summary.append(f"{C.G}{pos}:{ch}{C.E}")
                        else:
                            pos_summary.append(f"{C.R}{pos}:?{C.E}")
                    detail = " ".join(pos_summary)
                    print(f"  {C.D}  │  [row {offset}] {n_true}/{n_tests} TRUE | binary search: {detail}{C.E}")
                elif char_entries:
                    true_chars = sorted(
                        [(e["position"], e["char"]) for e in char_entries if e["is_true"]],
                        key=lambda x: x[0]
                    )
                    unique_chars = {}
                    for pos, ch in true_chars:
                        if pos not in unique_chars:
                            unique_chars[pos] = ch
                    char_detail = " ".join(
                        f"{C.G}{pos}:{repr(ch) if ch in (' ', '\t') else ch}{C.E}"
                        for pos, ch in sorted(unique_chars.items())
                    )
                    print(f"  {C.D}  │  [row {offset}] {n_true}/{n_tests} TRUE | chars: {char_detail}{C.E}")
                elif len_entries:
                    true_lens = [e["length_guess"] for e in len_entries if e["is_true"]]
                    len_str = str(true_lens[0]) if true_lens else "?"
                    print(f"  {C.D}  │  [row {offset}] length={len_str} ({n_true}/{n_tests} TRUE){C.E}")

            # Show reconstructed data
            print(f"  {C.CY}  ├─ Reconstructed ────────────────────────────────────{C.E}")
            for offset in sorted(reconstructed_rows.keys()):
                data = reconstructed_rows[offset]
                flags = find_flags(data)
                flag_marker = f"  {C.G}{C.BO}🚩 FLAG!{C.E}" if flags else ""
                print(f"  {C.G}{C.BO}  │  [row {offset}] → \"{data}\"{C.E}{flag_marker}")

            # Show string lengths if known
            if string_lengths:
                len_info = {f"row {k[0]}": v for k, v in string_lengths.items()}
                print(f"  {C.D}  ├─ String lengths: {len_info}{C.E}")

            print(f"  {C.CY}  └{'─'*55}{C.E}")
            all_targets[(column, table, where)] = reconstructed_rows

        print(f"\n{C.BO}  └{'─'*55}┘{C.E}")

    # ── Flag search in raw strings ──
    print(f"\n{C.CY}[*] Scanning raw pcapng for flags...{C.E}", end=" ")
    raw = run(f"strings '{pcap}'", timeout=15)
    raw_flags = find_flags(raw)
    if raw_flags:
        unique = list(set(raw_flags))
        print(f"{C.G}{len(unique)} found{C.E}")
        for f in unique:
            print(f"  {C.G}{C.BO}🚩 {f}{C.E}")
    else:
        print(f"{C.Y}none{C.E}")

    # ── Summary ──
    print(f"\n{C.BO}{C.CY}{'═'*65}")
    print(f"  SUMMARY")
    print(f"{'═'*65}{C.E}")
    print(f"  HTTP port            : {port}")
    print(f"  Total HTTP requests  : {len(all_reqs)}")
    print(f"  Blind SQLi requests  : {len(blind_reqs)}")
    print(f"  Extraction targets   : {len(all_targets)}")
    print(f"{'═'*65}{C.E}")

    # ── Interactive parameter export ──
    interactive_export(pcap, host, port, blind_reqs, all_classified_reqs, all_true_frames)


# ─── Interactive Export ─────────────────────────────────────────────────────

def interactive_export(pcap, host, port, blind_reqs, classified_reqs, true_frames):
    """Interactive parameter selection and JSON export."""
    if not classified_reqs:
        print(f"{C.D}  Done. Happy hunting! \U0001f6a9{C.E}\n")
        return

    # Build unique targets with metadata
    targets = []
    target_map = defaultdict(list)  # target_idx -> [(req, is_true)]
    seen = {}
    for req, is_true in classified_reqs:
        info = req["blind"]
        col = info.get("column", "?")
        tbl = info.get("table", "?")
        offset = info.get("offset", 0)
        typ = info.get("type", "char_compare")
        key = f"{col}@{tbl} (offset {offset})"
        if key not in seen:
            seen[key] = len(targets)
            targets.append({"key": key, "col": col, "table": tbl, "offset": offset, "type": typ})
        target_map[seen[key]].append((req, is_true))

    if not targets:
        print(f"{C.D}  Done. Happy hunting! \U0001f6a9{C.E}\n")
        return

    # Show numbered list
    print(f"\n{C.BO}{C.CY}[Parameter Export]{C.E}")
    print(f"  {C.CY}Select parameter to export:{C.E}")
    for i, t in enumerate(targets):
        print(f"    {C.G}[{i+1}]{C.E} {t['key']}  {C.D}({t['type']}){C.E}")
    print(f"    {C.G}[0]{C.E} Skip (no export)")

    try:
        choice = input(f"\n  {C.CY}[?] Pick number [0-{len(targets)}]: {C.E}").strip()
        idx = int(choice) - 1
    except (ValueError, KeyboardInterrupt):
        print(f"\n{C.D}  Skipped.{C.E}")
        print(f"{C.D}  Done. Happy hunting! \U0001f6a9{C.E}\n")
        return

    if idx < 0 or idx >= len(targets):
        print(f"  {C.D}Skipped.{C.E}")
        print(f"{C.D}  Done. Happy hunting! \U0001f6a9{C.E}\n")
        return

    # Pick filter: TRUE / FALSE / both
    try:
        filt = input(f"  {C.CY}[?] Filter: [1] TRUE  [2] FALSE  [3] Both → {C.E}").strip()
        filt_map = {"1": "true", "2": "false", "3": "both"}
        filter_choice = filt_map.get(filt, "both")
    except (KeyboardInterrupt, EOFError):
        filter_choice = "both"

    # Filter and build JSON
    selected = target_map[idx]
    params = []
    for req, is_true in selected:
        result = "true" if is_true else "false"
        if filter_choice == "true" and not is_true:
            continue
        if filter_choice == "false" and is_true:
            continue
        raw_uri = req.get("decoded_uri", req["uri"])
        parsed = urlparse(raw_uri)
        uri_path = parsed.path + ("?" + parsed.query if parsed.query else "")
        params.append({
            "frame":           str(req["frame"]),
            "method":          req["method"],
            "uri":             uri_path,
            "response_status": str(req.get("resp_status", "")),
            "response_size":   req["resp_size"],
            "result":          result,
        })

    # Sort by frame number
    params.sort(key=lambda x: int(x["frame"]))

    target_info = targets[idx]
    output = {
        "target":     f"{host}{urlparse(blind_reqs[0].get('full_uri', blind_reqs[0]['uri'])).path if blind_reqs else ''}",
        "parameter":  target_info["key"],
        "filter":     filter_choice,
        "total":      len(params),
        "parameters": params,
    }

    # Write JSON file
    basename = os.path.splitext(os.path.basename(pcap))[0]
    fname = f"{basename}_export_{target_info['col']}_offset{target_info['offset']}.json"
    with open(fname, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n  {C.G}[✓] Exported {len(params)} requests → {fname}{C.E}")
    print(f"{C.D}  Done. Happy hunting! \U0001f6a9{C.E}\n")


# ─── Entry Point ────────────────────────────────────────────────────────────

def main():
    print(f"""
{C.CY}{C.BO}╔══════════════════════════════════════════════════════════════╗
║     Boolean-Based Blind SQLi — PCAPNG Reconstructor         ║
║     Extract data character by character from capture files   ║
╚══════════════════════════════════════════════════════════════╝{C.E}
""")

    # Validate dependencies
    check_deps()

    if len(sys.argv) < 2:
        pcap = input(f"{C.CY}[?] Path to PCAPNG: {C.E}").strip()
    else:
        pcap = sys.argv[1]

    if not os.path.exists(pcap):
        print(f"{C.R}[!] File not found: {pcap}{C.E}")
        sys.exit(1)

    # Validate file is not empty and is a capture file
    if os.path.getsize(pcap) == 0:
        print(f"{C.R}[!] File is empty: {pcap}{C.E}")
        sys.exit(1)

    ext = os.path.splitext(pcap)[1].lower()
    if ext not in ('.pcap', '.pcapng', '.cap'):
        print(f"{C.Y}[!] Warning: '{ext}' may not be a valid capture file.{C.E}")

    mb = os.path.getsize(pcap) / (1024 * 1024)
    print(f"{C.G}[✓] Loaded: {pcap} ({mb:.2f} MB){C.E}\n")

    analyze(pcap)


if __name__ == "__main__":
    main()
