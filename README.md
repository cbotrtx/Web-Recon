# ◆ WEB-RECON — Advanced Web Reconnaissance Tool

**Version 1.0 · Author: cbotrtx** · Interactive CLI for authorized web reconnaissance.

**Requires PHP 8.0+** (uses `str_contains`/`str_starts_with`/`match`).

`php w_recon.php` → numbered menus guide you: target → protocol → scan type → depth → proxy → progress → summary → export.

## Quick start

```bash
php install.php      # check deps + init DB
php w_recon.php      # interactive mode
php w_recon.php --target=example.com --type=G --depth=2 --export=json   # non-interactive (never prompts)
php w_recon.php --target=example.com --modules=os,curl,ports --depth=1  # custom modules
php w_recon.php --target=example.com:8080 --modules=curl,headers        # explicit ports are honoured
```

Options accept `--opt=value` or `--opt value`. Invalid option values are rejected with an error instead of being silently ignored. Targets may be a hostname, IPv4, or IPv6 (`[2001:db8::1]:8443`), with an optional `:port`.

## Scan types

| Code | Name | Modules |
|------|------|---------|
| A | Basic Recon | dns, whois, geo, headers, curl |
| B | Infrastructure | dns, subdomain, ports, os, geo, whois |
| C | Technology | tech, cms, js, headers |
| D | Security | ssl, headers, waf, vuln, breach |
| E | API & Endpoints | urls, api, js, cloud |
| F | Custom | you pick (CLI: `--modules=...` is required) |
| G | Full Audit | all 18 modules |
| H | RED HAWK Feature Scan | G set + title, robots, subnet, mx, nmap, reverseip, sqli, bloggers, crawler |

Depth `1=Quick / 2=Standard / 3=Deep` controls port count (20 / ~90 / 1083), wordlist size, and protocol probes.

## Structure

```
w_recon.php  config.php  colors.php  install.php
core/ (Scanner, APIClient, Cache, Logger, Config)
cli/ (Menu, InputHandler, ProgressBar, CommandHandler)
modules/ (18 scanners: + OSDetector, CurlScanner)  integrations/ (Shodan, SecurityTrails, crt.sh, Wayback, HIBP, WHOIS)
output/ (JSON, CSV, HTML, Markdown, Terminal)  database/ (SQLite + JSON fallback)
assets/ (logo.png + ASCII fallback)  data/wordlists  templates/  results/  logs/
```

## API keys (optional)

Free modules work with no keys. For enrichment set env vars (or `config/api_keys.php` — it is loaded by `core/Config.php`):

```bash
export SHODAN_API_KEY=... SECURITYTRAILS_API_KEY=... HIBP_API_KEY=...
```

## Output

- Terminal summary + `results/<target>_<ts>.json` snapshot every scan
- Export to JSON / CSV / HTML / Markdown; SQLite history in `database/wrecon.sqlite`
- Logs in `logs/wrecon_YYYY-MM-DD.log`
- Runtime artifacts (`results/`, `cache/`, `logs/`, `database/*.sqlite`) are git-ignored — scan data stays local

## Ethics

Authorized targets only. No exploitation — heuristic checks + banner/DNS/HTTP analysis.
