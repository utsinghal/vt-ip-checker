# VirusTotal IP Blocklist Builder (free API)

Scans the external IPs from any list or SIEM export on VirusTotal. It builds a blocklist of every IP that
**at least one vendor explicitly marks as malicious**, and saves a cropped proof screenshot for each one.

## One-time setup
Requires Windows with Python 3.10+ and Microsoft Edge.

0. Clone the repo and double-click `run.bat` once. It creates `.venv`, installs the dependencies, and
   copies the `*.example.txt` templates to `vt_api_key.txt`, `internal_ranges.txt` and `ips.txt`.
   Those three files are git-ignored, so your keys and IPs are never committed.
1. Create a free VirusTotal account, then copy your key from https://www.virustotal.com/gui/my-apikey
2. Paste the key into `vt_api_key.txt`. You can add several keys, **one per line**. They are used in rotation,
   and each key adds 4 lookups/min and 500 lookups/day. A key that runs out of quota or is rejected is dropped automatically.
3. Optional: put your organisation's own public IPs/ranges into `internal_ranges.txt` so they are never scanned.

Manual install: `python -m venv .venv && .venv\Scripts\pip install -r requirements.txt`

## Run
- **Drag a CSV/text file onto `run.bat`**. A Kibana/Elastic export works as-is, because IPs are pulled from any column.
- Or put IPs in `ips.txt` and double-click `run.bat`.
- Or from the command line: `.venv\Scripts\python vt_checker.py -i "export.csv"`

## Rules
- **Internal IPs are excluded** and never sent to VirusTotal. This covers 10/8, 172.16/12, 192.168/16, loopback,
  CGNAT 100.64/10, link-local and other reserved ranges, plus anything in `internal_ranges.txt`.
- **Only explicit "malicious" verdicts count.** An IP flagged only as "suspicious" is left out of the blocklist.
  It still appears as Clean (yellow) in the *All Results* sheet so you can see it.

## Output: a new folder for each scan
```
output\ip_blocklist_29_sep\          first scan of the day
    ip_blocklist_29_sep.xlsx         Malicious IPs (with embedded screenshots) / All Results / Run Info
    ip_blocklist_29_sep.html         same report for a browser
    ip_blocklist_29_sep.txt          blocklist: malicious IPs only, one per line
    screenshots\                     one proof PNG per malicious IP
    raw\                             raw VirusTotal API JSON (audit trail)
output\ip_blocklist_29_sep_2\        second scan the same day, and so on
```

## Useful options
| Option | Meaning |
|---|---|
| `--min-detections 2` | Require 2+ vendors saying malicious (default 1) |
| `--screenshot card` | Don't visit the VT website; render the evidence card from API data |
| `--screenshot none` | No screenshots |
| `--show-browser` | Show the browser window, e.g. if VT shows a captcha to solve |
| `--api-key KEY` | Add a key from the command line (can be repeated) |

## Free-tier limits
- 4 lookups per minute and 500 per day **per key**. With 1 key, 100 IPs take about 26 min. With 3 keys, about 9 min.
- Results are cached for 24 h in `.cache\`, so rescanning the same IPs costs no quota.
- If you press Ctrl+C, a report is still written for the IPs checked so far.
