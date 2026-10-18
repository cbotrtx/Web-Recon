# ◆ WEB-RECON — Advanced Web Reconnaissance Tool

**Version 1.0 · Author: cbotrtx** · Interactive CLI for authorized web reconnaissance.

`php w_recon.php` → numbered menus guide you: target → protocol → scan type → depth → proxy → progress → summary → export.

## Quick start

```bash
./install.php        # check deps + init DB  (`php` prefix also works)
./w_recon.php        # interactive mode
./w_recon.php --target=example.com --type=G --depth=2 --export=json  # non-interactive
./w_recon.php --target=example.com --modules=os,curl,ports --depth=1  # custom modules
```

## Scan types

| Code | Name | Modules |
|------|------|---------|
| A | Basic Recon | dns, whois, geo, headers, curl |
| B | Infrastructure | dns, subdomain, ports, os, geo, whois |
| C | Technology | tech, cms, js, headers |
| D | Security | ssl, headers, waf, vuln, breach |
| E | API & Endpoints | urls, api, js, cloud |
| F | Custom | you pick |
| G | Full Audit | all 18 modules |

Depth `1=Quick / 2=Standard / 3=Deep` controls port count, wordlist size, and protocol probes.

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

Free modules work with no keys. For enrichment set env vars (or `config/api_keys.php`):

```bash
export SHODAN_API_KEY=... SECURITYTRAILS_API_KEY=... HIBP_API_KEY=...
```

## Output

- Terminal summary + `results/<target>_<ts>.json` snapshot every scan
- Export to JSON / CSV / HTML / Markdown; SQLite history in `database/wrecon.sqlite`
- Logs in `logs/wrecon_YYYY-MM-DD.log`

## Ethics

Authorized targets only. No exploitation — heuristic checks + banner/DNS/HTTP analysis.
