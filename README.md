# MX Tools

A web-based toolkit for diagnosing email infrastructure. Runs as a local Flask
service and covers the practical checks an admin needs when something is wrong
with mail delivery: SPF, DMARC, DKIM, MX, DNSBL blacklists, SMTP connectivity,
mailbox existence probing, reverse DNS, TLS certificates, MTA-STS, TLS-RPT,
BIMI, role accounts, and catch-all detection - without touching the command
line or remembering `dig` flags.

## Features

### Full check
One-shot diagnosis for a domain or a full email address:
- **scoring checks** (SPF, DMARC, DKIM, MX, Blacklist) determine the final
  "N/M checks passed" verdict - these are what defines whether a domain is
  healthy
- **informational checks** (SMTP connectivity, Mailbox) are shown in full but
  never lower the score, because they depend on the probing host's network
  (outbound port 25 is blocked on most VPS providers) or on a single mailbox,
  not on the domain itself
- for an email input, the mailbox probe is added automatically

### SPF check
Look up the domain's TXT SPF record and validate it:
- full syntax parsing, `include`, `a`, `mx`, `redirect`, `exp`
- DNS lookup counter against the RFC 7208 limit of 10
- warnings and errors returned as a list, not a single opaque message

### DMARC check
Query the `_dmarc` subdomain and interpret the record:
- tags `p`, `sp`, `rua`, `ruf`, `pct`, `adkim`, `aspf`, `fo`
- policy in effect, reporting addresses, warnings

### DKIM check
Look up `<selector>._domainkey.example.com`:
- with a specific selector - shows parsed tags and the public key hint
- without a selector - probes ~15 common selectors in parallel and reports
  which ones resolve
- flags `v=DKIM1` mismatches and empty `p=` keys

### MX lookup
- MX records sorted by priority
- `A`/`AAAA` resolution behind each exchange
- TCP port 25 reachability from this host (shown but not part of the verdict)

### Blacklist check
- resolves the domain to an IPv4 address
- queries 12 popular DNSBLs: Spamhaus ZEN, SpamCop, Barracuda, SORBS (two
  zones), PSBL, UCEPROTECT L1, s5h.net, Mailspike, JustSpam, SpamSources,
  blocklist.de
- distinguishes "listed", "clean", and "could not check"

### SMTP connectivity test
For every MX host, on every IP, in parallel across four ports:
- **25** plain
- **587** STARTTLS
- **2525** plain
- **465** implicit TLS

Returns the banner, the supported ESMTP extensions, whether `STARTTLS` really
succeeded, and the resulting cipher set.

### Mailbox existence check
Performs `MAIL FROM:<>` followed by `RCPT TO:<address>` and interprets the
response:
- uses the null sender to bypass SPF/DKIM on `MAIL FROM` (bounce-style, per
  RFC 5321)
- probes the same four ports as SMTP test, in parallel
- understands RFC 3463 enhanced status codes (`5.1.1`, `5.7.1`, `4.2.0`, ...)
  with a text fallback (`unknown user`, `relay denied`, `greylist`, ...)
- optional **Server** field: probe a specific IP or hostname instead of the
  domain's MX records
- verdicts: `exists`, `not_exists`, `rejected`, `rejected_policy`,
  `temp_fail`, `unreachable`, `inconclusive`

### PTR check
Resolves each MX host to its IPv4 addresses and looks up the PTR record:
- shows every PTR entry for every IPv4 address of every MX
- flags IPs with no PTR at all and IPs whose PTR does not match the MX
  hostname
- the mismatch count is a direct deliverability signal: forward-confirmed
  reverse DNS mismatch is penalised by many receiving MTAs

### TLS certificate check
Connects to every MX host on port 25, performs `STARTTLS`, and inspects the
presented certificate:
- issuer and subject
- `notAfter` and remaining days (tagged red if expired, orange if under 30
  days, green otherwise)
- the full `subjectAltName` list
- hostname match against the MX hostname
- graceful per-IP errors: `STARTTLS not advertised`, `STARTTLS failed`,
  timeouts

### MTA-STS check
Validates SMTP MTA Strict Transport Security (RFC 8461):
- looks up `_mta-sts.<domain>` TXT for `v=STSv1`
- fetches `https://mta-sts.<domain>/.well-known/mta-sts.txt`
- parses `version`, `mode`, `max_age`, and the `mx:` host list
- flags `mode` values other than `enforce`

### TLS-RPT check
Validates SMTP TLS Reporting (RFC 8460):
- looks up `_smtp._tls.<domain>` TXT for `v=TLSRPTv1`
- extracts and lists the `rua=` reporting destinations
- warns when `rua=` is empty

### BIMI check
Validates Brand Indicators for Message Identification:
- looks up `default._bimi.<domain>` TXT for `v=BIMI1`
- parses `l=` (logo URL) and `a=` (VMC authority)
- performs a HEAD on `l=` and requires a `200` response with
  `image/svg+xml`
- warns when the logo is missing or is not an SVG

### Role accounts check
Probes RFC 2142 role addresses on the domain's primary (lowest-priority) MX:
- `postmaster@`, `abuse@`, `hostmaster@`, `webmaster@`
- reports `RCPT TO` code, message, and existence per role
- `postmaster@` and `abuse@` are required by RFC 2142 - their absence is
  raised as a red verdict
- requires outbound port 25

### Catch-all check
Probes a random non-existent mailbox on the primary MX:
- `250`/`251` on a random `RCPT TO` means catch-all is enabled
- warns when catch-all is on: it silently inflates the mailbox check
  verdict, invites backscatter, and makes every typo address reachable
- requires outbound port 25

## Stack

- **Backend:** Python, Flask, `dnspython`, `checkdmarc`, `requests`,
  standard-library `smtplib`, `ssl`, `socket`
- **Frontend:** a single HTML file with vanilla JavaScript, no build step
- **Storage:** none - every request is stateless

## Requirements

- Python 3.10+
- `checkdmarc` >= 5.7 (SPF/DMARC record parsing)
- `dnspython` >= 2.6 (MX, TXT, A/AAAA, PTR, DNSBL queries)
- `requests` >= 2.31 (MTA-STS policy fetch, BIMI logo fetch)
- Outbound TCP to port 53 on some resolver
- Outbound HTTPS for the MTA-STS and BIMI checks
- **Outbound TCP to ports 25, 587, 2525, 465** for SMTP, mailbox, TLS
  certificate, role account, and catch-all checks. Most cloud providers
  block outbound 25; without it, the mailbox probe can only rely on
  587/2525/465 and only on servers that do not require AUTH for `RCPT TO`,
  while the TLS certificate, role account, and catch-all checks against
  remote MX hosts will show as unreachable.

## Installation

```bash
git clone https://github.com/arkain123/mx.mare.of.by
cd mx.mare.of.by

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

Example `requirements.txt`:

```
flask
python-dotenv
dnspython>=2.6
checkdmarc>=5.7
```

## Usage

```bash
python app.py
```

Then open `http://<FLASK_HOST>:<FLASK_PORT>` in a browser (by default,
`http://127.0.0.1:5000`).

The UI has one tab per check:

- **Full check** - domain or email, runs everything in parallel and shows a
  `N/M` score over the scoring checks only.
- **SPF / DMARC / DKIM / MX / Blacklist** - single-purpose checks with a
  detailed result table.
- **SMTP** - banner and ESMTP feature dump per MX IP per port.
- **Mailbox** - RCPT probe. Optional **Server** field to target a specific
  IP or hostname instead of the domain's MX records.
- **🌓** - cycles the theme: `auto → dark → light`, persisted in
  `localStorage`.

## Supported checks

### Scoring (part of the Full check verdict)

| Check        | What it answers                                                         |
|--------------|-------------------------------------------------------------------------|
| SPF          | Is there an SPF record, is it syntactically valid, is it under 10 lookups |
| DMARC        | Is there a `_dmarc` record, is it valid, what policy is in effect       |
| DKIM         | Is there a DKIM key published for at least one common selector          |
| MX           | Do MX records exist (port 25 reachability is informational only)        |
| Blacklist    | Is the domain's IPv4 listed on any of 12 DNSBLs                         |

### Informational (never lowers the score)

| Check                | What it answers                                                  |
|----------------------|------------------------------------------------------------------|
| SMTP connectivity    | Is any port (25/587/2525/465) reachable on any MX IP from here   |
| Mailbox existence    | Does `<address>` resolve on the target SMTP server               |

## Project layout

```
.
├── app.py                 # Flask app and HTTP routes
├── checkers/
│   ├── __init__.py
│   ├── spf.py             # SPF lookup, wraps checkdmarc
│   ├── dmarc.py           # DMARC lookup, wraps checkdmarc
│   ├── dkim.py            # DKIM selector lookup, parallel auto-detect
│   ├── mx.py              # MX records + port 25 reachability
│   ├── blacklist.py       # DNSBL queries
│   ├── smtp.py            # SMTP connectivity across four ports
│   ├── mailbox.py         # RCPT probe (MX or custom server)
│   └── full.py            # Parallel orchestrator for the Full check
├── templates/
│   └── index.html         # Single-page UI
├── static/
│   ├── style.css          # Theme tokens and components (light + dark)
│   └── script.js          # Tabs, renderers, form submission
└── requirements.txt
```

## API

All endpoints accept and return JSON. `POST`, `Content-Type: application/json`.

| Method | Endpoint          | Purpose                                              |
|--------|-------------------|------------------------------------------------------|
| POST   | `/api/full`       | Run all checks for a domain or an email address      |
| POST   | `/api/spf`        | Check the SPF record                                 |
| POST   | `/api/dmarc`      | Check the DMARC record                               |
| POST   | `/api/dkim`       | Check a DKIM selector (or auto-detect)               |
| POST   | `/api/mx`         | Lookup MX records and test port 25                   |
| POST   | `/api/blacklist`  | Check the domain's IP against DNSBLs                 |
| POST   | `/api/smtp`       | Test SMTP on 25/587/2525/465 for every MX IP         |
| POST   | `/api/mailbox`    | Probe a mailbox via RCPT TO                          |

### Payloads

`/api/full`:

```json
{ "domain": "example.com or user@example.com" }
```

`/api/spf`, `/api/dmarc`, `/api/mx`, `/api/blacklist`, `/api/smtp`:

```json
{ "domain": "example.com" }
```

`/api/dkim`:

```json
{ "domain": "example.com", "selector": "default" }
```

`selector` is optional. Without it, ~15 common selectors are tried in parallel.

`/api/mailbox`:

```json
{ "email": "user@example.com", "server": "1.2.3.4 or mx.example.com" }
```

`server` is optional. Without it, the domain's MX records are used. With it,
the probe goes directly to the given IP or hostname and skips MX resolution.

### Response for `/api/mailbox`

```json
{
  "valid": false,
  "connected": true,
  "email": "user@example.com",
  "domain": "example.com",
  "verdict": "not_exists",
  "server": "1.2.3.4",
  "mx_source": "custom-server",
  "mx_chain": [
    { "priority": 0, "host": "1.2.3.4", "custom": true,
      "ipv4": ["1.2.3.4"], "ipv6": [] }
  ],
  "attempts": [
    { "ip": "1.2.3.4", "port": 25, "tls": "plain", "connected": true,
      "banner": "220 mail.example.com ESMTP",
      "mail_from_code": 250, "mail_from_msg": "2.1.0 Ok",
      "rcpt_code": 550, "rcpt_msg": "5.1.1 user unknown",
      "status": "not_exists" }
  ]
}
```

`valid` is `true` only when `verdict == "exists"`. `connected` tells you
whether a TCP connection was established at all - a `550` with
`connected: true` is a definitive "no such mailbox", not a network error.

### Response for `/api/full`

```json
{
  "domain": "example.com",
  "email": null,
  "summary": { "passed": 5, "total": 5, "score": "5/5" },
  "checks": [
    { "key": "spf",  "label": "SPF",  "status": "pass", "scoring": true,
      "detail": null, "result": {  } },
    { "key": "smtp", "label": "SMTP connectivity", "status": "info",
      "scoring": false,
      "detail": "no SMTP port reachable from this host ...",
      "result": {  } }
  ]
}
```

`summary.passed` / `summary.total` count only checks with `"scoring": true`.
Informational entries are still present in `checks[]` with `"status": "info"`
and a full `result` block.

## Security notes

- Do not expose it publicly without authentication and TLS in front of it.
  The mailbox probe opens outbound SMTP connections, and a public instance
  will be abused as a scanning relay.
- The mailbox check sends `RCPT TO` to remote servers. On large scales this
  looks like directory harvesting and can get your IP listed. Rate-limit the
  endpoint and do not loop it over address lists.
- DNSBL services (Spamhaus in particular) prohibit queries from public
  resolvers and from open proxies. Run the service behind a resolver that
  your IP is entitled to use; a `127.255.255.254` answer from Spamhaus means
  your query was blocked, not that the target is listed.
- Do not point `SMTP_PORTS` at arbitrary ports; the probe sends protocol data
  immediately.

## Limitations

- **Catch-all servers always answer `250`.** If `RCPT TO:<random-42@domain>`
  gets `250`, the mailbox check cannot distinguish real from fabricated
  addresses. This is a protocol limitation, not a bug.
- **Greylisting.** A `4.x.x` answer (`temp_fail`) means "retry later", not
  "no mailbox". Retry after 1–5 minutes for a definitive result.
- **Port 25 is blocked on most VPS providers.** SMTP and mailbox checks fall
  back to 587/2525/465, but submission ports usually require AUTH before
  `RCPT TO`. Expect `530 auth required` on them, which is classified as
  `rejected_policy`, not `not_exists`.
- **Spamhaus and some DNSBLs** return `127.255.255.254` for queries from
  public resolvers (Google, Cloudflare). Use a local recursive resolver to
  get real answers.
- **DKIM auto-detect** covers ~15 popular selectors (Google, Microsoft
  `selector1/selector2`, Mailchimp, Amazon SES, Mandrill, ProtonMail, etc.).
  Custom selectors must be entered explicitly.
- **SPF/DMARC validation** is delegated to `checkdmarc`. It follows RFC 7208
  and RFC 7489, but the warnings it emits are advisory, not authoritative.
- **IPv6 probing** only runs if the current host has IPv6 connectivity.
  On IPv4-only VPSes, IPv6 attempts will time out and show as
  `connect_error` in `attempts[]`.
- **No historical data.** Every request is stateless; nothing is stored.
