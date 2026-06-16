# BBS-PCAPNG — Boolean-Based Blind SQLi PCAPNG Reconstructor

Tool untuk mendeteksi dan me-reconstruct data dari **boolean-based blind SQL injection** yang terekam dalam file PCAPNG. Dirancang khusus untuk CTF kategori Network Forensics.

## Fitur

- **Auto-detect HTTP port** — scanning frekuensi `tcp.dstport` (support port 1–65535)
- **3 teknik blind SQLi yang di-support:**
  - `substr(col, pos, 1) = 'char'` — char comparison
  - `unicode(substr(col, pos, 1)) >= N` — binary search
  - `length(col) = N` — length enumeration
- **Hybrid response classification** — JSON semantic parsing + frequency analysis fallback
- **Nested subquery support** — `substr((SELECT col FROM tbl ...), pos, 1)`
- **Comment marker support** — `--`, `--+`, `#`, `/*`
- **Multi-row reconstruction** — grouping by table, column, offset
- **Interactive parameter export** — pilih parameter & filter (TRUE/FALSE/both), export ke JSON
- **Flag auto-detection** — scan hasil reconstruct + raw strings di pcap

## Prasyarat

- **Python 3.8+**
- **tshark** (bagian dari Wireshark)
- **strings** (bagian dari binutils)

### Install Dependencies (Kali Linux / Debian)

```bash
sudo apt install tshark binutils python3
```

## Cara Pakai

### Basic Usage

```bash
python3 sqli_detector.py <file.pcapng>
```

### Interactive Mode

```bash
python3 sqli_detector.py
# Akan muncul prompt: Path to PCAPNG:
```

### Contoh Output

```
╔══════════════════════════════════════════════════════════════╗
║     Boolean-Based Blind SQLi — PCAPNG Reconstructor         ║
║     Extract data character by character from capture files   ║
╚══════════════════════════════════════════════════════════════╝

[✓] Loaded: challenge.pcapng (2.45 MB)

[*] Scanning for HTTP port... 5000
[*] Extracting HTTP traffic (bulk)... 3239 requests
[*] Scanning for boolean-based blind SQLi...

═══════════════════════════════════════════════════════════════
  BOOLEAN-BASED BLIND SQLi DETECTED
═══════════════════════════════════════════════════════════════

  Target  : 127.0.0.1:5000/api/search
  Payloads: 3239 blind requests

  ┌─ Response Analysis ─────────────────────────────────┐
    TRUE  responses : 812 (character match!)
    FALSE responses : 2427 (no match)
  └───────────────────────────────────────────────────────┘

  ┌─ Data Extraction ───────────────────────────────────┐
    ┌─ password@users [table] (char_compare)
    │  WHERE: username='admin'
    │  [row 0] 812/3239 TRUE | chars: 1:'L' 2:'K' 3:'S' ...
    ├─ Reconstructed ────────────────────────────────────
    │  [row 0] → "LKS{Xf!ltr4tr10n_SQLi_asique}"  🚩 FLAG!
    └───────────────────────────────────────────────────────
  └───────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════
  SUMMARY
═══════════════════════════════════════════════════════════════
  HTTP port            : 5000
  Total HTTP requests  : 3239
  Blind SQLi requests  : 3239
  Extraction targets   : 3
═══════════════════════════════════════════════════════════════
```

### Parameter Export

Setelah scan selesai, muncul menu interaktif:

```
[Parameter Export]
  Select parameter to export:
    [1] password@users (offset 0)  (char_compare)
    [2] api_key@admins (offset 0)  (binary_search)
    [3] name@sqlite_master (offset 0)  (length_enum)
    [0] Skip (no export)

  [?] Pick number [0-3]: 1
  [?] Filter: [1] TRUE  [2] FALSE  [3] Both → 1

  [✓] Exported 812 requests → challenge_export_password_offset0.json
```

### Format JSON Export

```json
{
  "target": "127.0.0.1:5000/api/search",
  "parameter": "password@users (offset 0)",
  "filter": "true",
  "total": 812,
  "parameters": [
    {
      "frame": "142",
      "method": "GET",
      "uri": "/api/search?q=' OR substr(password,1,1)='L' -- ",
      "response_status": "200",
      "response_size": 18,
      "result": "true"
    }
  ]
}
```

## SQLi Patterns yang Di-support

| Teknik | Payload Pattern | Contoh |
|--------|----------------|--------|
| Char Compare | `substr(col,pos,1)='c'` | `substr(password,1,1)='A'` |
| Nested Subquery | `substr((SELECT col FROM tbl),pos,1)='c'` | `substr((SELECT api_key FROM admins),1,1)='f'` |
| Binary Search | `unicode(substr(col,pos,1))>=N` | `unicode(substr(password,1,1))>=65` |
| Length Enum | `length(col)=N` | `length((SELECT password FROM users))=32` |

## Catatan

- Tool ini **hanya** untuk boolean-based blind SQLi (bukan time-based, union-based, dll)
- Response classification otomatis via JSON body parsing atau frequency analysis
- Support table alias (misal `u.password` → `password`)
- Support URL encoding berlapis (triple decode + `+` as space)

## Lisensi

MIT
