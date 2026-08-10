# access-log-abuse-detector

Detect web abuse in access logs: credential stuffing, endpoint enumeration,
automated scanners, and high error rates per source IP. Emits ranked indicators
and a suggested blocklist. Pure Python standard library, no dependencies.

> **Goal:** turn a noisy access log into a short list of IPs worth blocking and
> the evidence for why.

## What it does

- Parses Common/Combined Log Format (nginx/Apache), tolerates malformed lines
- Aggregates per source IP: requests, failed auth, 404s, error responses, unique paths, user-agents
- Flags:
  - `credential_stuffing` - repeated failed auth (`POST`/`PUT` to auth paths returning 401/403/429)
  - `enumeration` - excessive 404s across many paths
  - `scanner` - known offensive-tool user-agents (sqlmap, nikto, nuclei, etc.)
  - `high_error_rate` - high share of error responses over a request floor
- Severity-ranked report, optional JSON, and a suggested blocklist (high+ by default)
- Reads from a file or stdin; non-zero exit when a blocklist is produced

## Files

- `access_log_abuse.py` - CLI and detection engine
- `sample-access.log` - example log (generated; see below)
- `test_access_log_abuse.py` - unit tests

## Usage

```bash
python3 access_log_abuse.py sample-access.log --json findings.json --blocklist block.txt

# from stdin
cat /var/log/nginx/access.log | python3 access_log_abuse.py -
```

## Test

```bash
python3 -m unittest -v
```

## Disclaimer

This repository reflects personal study and practice. It contains no employer
logs or data; the sample log is synthetic. Thresholds are conservative defaults
and will need tuning for your traffic. Provided as-is; validate against your own
context.

## License

MIT. See [LICENSE](LICENSE).
