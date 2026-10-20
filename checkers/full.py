from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout

from . import spf, dmarc, dkim, mx, blacklist, smtp, mailbox


# Only these checks contribute to the score.
SCORING_KEYS = {"spf", "dmarc", "dkim", "mx", "blacklist"}


def _split_input(raw):
    s = raw.strip()
    if "@" in s:
        local, _, domain = s.rpartition("@")
        if local and domain:
            return domain.lower().rstrip("."), s
    return s.lower().rstrip("."), None


def _st_spf(r):
    return ("pass", None) if r.get("valid") else ("fail", r.get("error") or "invalid SPF")


def _st_dmarc(r):
    return ("pass", None) if r.get("valid") else ("fail", r.get("error") or "invalid DMARC")


def _st_dkim(r):
    if r.get("valid"):
        return ("pass", None)
    if r.get("error", "").startswith("No DKIM record"):
        return ("warn", "not found on common selectors (may be custom)")
    return ("fail", r.get("error") or "invalid DKIM")


def _st_mx(r):
    # MX existence is critical: without MX the domain cannot receive mail.
    # Port 25 reachability is NOT part of the verdict.
    if not r.get("valid"):
        return ("fail", r.get("error") or "no MX records")
    return ("pass", None)


def _st_blacklist(r):
    if not r.get("valid"):
        return ("fail", r.get("error") or "lookup failed")
    listed = r.get("listed_count", 0)
    if listed:
        names = ", ".join(x["label"] for x in r.get("results", []) if x.get("listed") is True)
        return ("fail", "listed on {}: {}".format(listed, names))
    if any(x.get("listed") is None for x in r.get("results", [])):
        return ("warn", "some blacklists could not be checked")
    return ("pass", None)


def _st_smtp(r):
    # Informational only. Outbound 25 is blocked on many VPSes and this
    # says nothing about the domain's mail health.
    if r.get("error"):
        return ("info", r["error"])
    if not r.get("hosts"):
        return ("info", "no MX hosts to probe")
    for h in r["hosts"]:
        for a in h.get("attempts", []):
            if a.get("status") == "ok":
                return ("info", "reachable from this host on at least one port")
    return ("info", "no SMTP port reachable from this host (port 25 often blocked on VPSes)")


def _st_mailbox(r):
    # Informational only. A missing mailbox is about a user, not the domain.
    v = r.get("verdict")
    mapping = {
        "exists": "mailbox exists",
        "not_exists": "mailbox does not exist",
        "rejected": "server rejects RCPT without revealing user",
        "rejected_policy": "probe blocked by server policy",
        "unreachable": "no SMTP port reachable from this host",
    }
    return ("info", mapping.get(v, r.get("error") or "inconclusive"))


def check(raw_input):
    domain, email = _split_input(raw_input)

    tasks = {
        "spf": (spf.check, _st_spf, "SPF"),
        "dmarc": (dmarc.check, _st_dmarc, "DMARC"),
        "dkim": (dkim.check, _st_dkim, "DKIM"),
        "mx": (mx.check, _st_mx, "MX"),
        "blacklist": (blacklist.check, _st_blacklist, "Blacklist"),
        "smtp": (smtp.check, _st_smtp, "SMTP connectivity"),
    }
    if email:
        tasks["mailbox"] = (
            lambda _d, e=email: mailbox.check(e),
            _st_mailbox,
            "Mailbox",
        )

    results = {}
    with ThreadPoolExecutor(max_workers=len(tasks)) as ex:
        futures = {k: ex.submit(fn, domain) for k, (fn, _, _) in tasks.items()}
        for k, fut in futures.items():
            try:
                results[k] = fut.result(timeout=60)
            except FutTimeout:
                results[k] = {"valid": False, "error": "timeout"}
            except Exception as e:
                results[k] = {"valid": False, "error": str(e)}

    checks = []
    passed = 0
    scoring_total = 0
    for key, (_, status_fn, label) in tasks.items():
        status, detail = status_fn(results[key])
        scoring = key in SCORING_KEYS
        if scoring:
            scoring_total += 1
            if status == "pass":
                passed += 1
        checks.append({
            "key": key,
            "label": label,
            "status": status,
            "detail": detail,
            "scoring": scoring,
            "result": results[key],
        })

    return {
        "input": raw_input,
        "domain": domain,
        "email": email,
        "summary": {
            "passed": passed,
            "total": scoring_total,
            "score": "{}/{}".format(passed, scoring_total),
        },
        "checks": checks,
    }
