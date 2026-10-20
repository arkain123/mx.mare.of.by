import ipaddress
import re
import smtplib
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.resolver

TIMEOUT = 6
SMTP_PORTS = [(25, "plain"), (587, "starttls"), (2525, "plain"), (465, "ssl")]
PORT_ORDER = {p: i for i, (p, _) in enumerate(SMTP_PORTS)}

NOT_EXISTS_HINTS = (
    "unknown user", "user unknown", "no such user", "user not found",
    "unknown mailbox", "mailbox not found", "mailbox unavailable",
    "invalid recipient", "invalid mailbox", "recipient not found",
    "does not exist", "doesn't exist", "no such recipient",
    "not a valid mailbox", "user does not exist", "unknown account",
    "unrouteable address", "unrouteable mail domain",
    "recipient address rejected",
    "пользователь не найден", "нет такого пользователя",
    "адресат не найден", "ящик не найден", "не существует",
)

POLICY_HINTS = (
    "relay", "relaying denied", "not permitted", "not authorized",
    "policy", "spam", "blocked", "blacklist", "banned", "abuse",
    "spf", "dkim", "dmarc", "authentication required", "auth required",
    "access denied", "sender address rejected", "client host rejected",
    "try again later", "greylist",
)


def _decode(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if value is None:
        return ""
    return str(value)


def _parse_email(raw):
    s = (raw or "").strip()
    if "@" not in s:
        return None
    local, _, domain = s.rpartition("@")
    if not local or not domain:
        return None
    return {"email": s, "local": local, "domain": domain.lower().rstrip(".")}


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _resolve_server(server):
    """Resolve a user-provided server (IP or hostname) to an IP list.
    Returns the same shape as _resolve_mx_chain so downstream code is unchanged."""
    if _is_ip(server):
        ip_obj = ipaddress.ip_address(server)
        entry = {
            "priority": 0, "host": server, "custom": True,
            "ipv4": [server] if ip_obj.version == 4 else [],
            "ipv6": [server] if ip_obj.version == 6 else [],
        }
        return {"source": "custom-server", "chain": [entry]}

    v4, v6 = [], []
    try:
        for r in dns.resolver.resolve(server, "A", lifetime=5.0):
            v4.append(str(r))
    except Exception:
        pass
    try:
        for r in dns.resolver.resolve(server, "AAAA", lifetime=5.0):
            v6.append(str(r))
    except Exception:
        pass
    entry = {
        "priority": 0, "host": server, "custom": True,
        "ipv4": v4, "ipv6": v6,
    }
    return {"source": "custom-server", "chain": [entry]}


def _ehlo_name(hostname, email_domain):
    """EHLO argument must be a hostname or address literal, never a bare IP."""
    if _is_ip(hostname):
        return email_domain
    return hostname


def _resolve_mx_chain(domain):
    mx_pairs = []
    source = "mx"
    try:
        for r in dns.resolver.resolve(domain, "MX", lifetime=8.0):
            mx_pairs.append((int(r.preference), str(r.exchange).rstrip(".")))
        mx_pairs.sort(key=lambda x: x[0])
    except Exception:
        pass

    if not mx_pairs:
        source = "a-record-fallback"
        mx_pairs = [(0, domain)]

    chain = []
    for prio, host in mx_pairs:
        v4, v6 = [], []
        try:
            for r in dns.resolver.resolve(host, "A", lifetime=5.0):
                v4.append(str(r))
        except Exception:
            pass
        try:
            for r in dns.resolver.resolve(host, "AAAA", lifetime=5.0):
                v6.append(str(r))
        except Exception:
            pass
        chain.append({"priority": prio, "host": host, "ipv4": v4, "ipv6": v6})
    return {"source": source, "chain": chain}


def _interpret_rcpt(code, msg):
    # Accept bytes / None / str — never raise.
    if isinstance(msg, bytes):
        msg = msg.decode("utf-8", errors="replace")
    msg = msg or ""
    low = msg.lower()

    m = re.search(r"\b([245])\.(\d{1,3})\.(\d{1,3})\b", msg)
    if m:
        cls, sub, det = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if cls == 2:
            return "exists"
        if cls == 4:
            return "temp_fail"
        if cls == 5:
            if sub == 1 and det in (1, 6, 10):
                return "not_exists"
            if sub == 7:
                return "rejected_policy"
            return "rejected"

    if code in (250, 251):
        return "exists"

    if any(h in low for h in NOT_EXISTS_HINTS):
        return "not_exists"
    if any(h in low for h in POLICY_HINTS):
        return "rejected_policy"

    if code in (450, 451, 452, 421):
        return "temp_fail"
    if code == 530:
        return "rejected_policy"
    if code in (551, 553, 554):
        return "rejected"
    if code == 550:
        return "not_exists"
    if 400 <= code < 500:
        return "temp_fail"
    if 500 <= code < 600:
        return "rejected"
    return "other_{}".format(code)


def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _probe(ip, hostname, port, tls_mode, target):
    out = {
        "ip": ip, "hostname": hostname, "port": port, "tls": tls_mode,
        "status": "unknown", "connected": False,
    }
    smtp = None
    try:
        if tls_mode == "ssl":
            smtp = smtplib.SMTP_SSL(ip, port, timeout=TIMEOUT, context=_ssl_ctx())
        else:
            smtp = smtplib.SMTP(ip, port, timeout=TIMEOUT)
    except (socket.timeout, TimeoutError):
        out["status"] = "connect_error"
        out["error"] = "connect timeout"
        return out
    except ConnectionRefusedError:
        out["status"] = "connect_error"
        out["error"] = "connection refused"
        return out
    except OSError as e:
        out["status"] = "connect_error"
        out["error"] = "{}: {}".format(type(e).__name__, e)
        return out
    except Exception as e:
        out["status"] = "connect_error"
        out["error"] = "{}: {}".format(type(e).__name__, e)
        return out

    try:
        out["connected"] = True

        try:
            out["banner"] = _decode(smtp.getwelcome())[:200]
        except Exception as e:
            out["banner_error"] = "{}: {}".format(type(e).__name__, e)

        try:
            smtp.ehlo(hostname)
        except smtplib.SMTPException:
            try:
                smtp.helo(hostname)
            except smtplib.SMTPException as e:
                out["status"] = "smtp_error"
                out["error"] = "helo failed: {}".format(e)
                return out

        features = smtp.esmtp_features or {}
        out["supports_starttls"] = "starttls" in features

        if tls_mode == "starttls":
            if "starttls" in features:
                try:
                    smtp.starttls(context=_ssl_ctx())
                    smtp.ehlo(hostname)
                    out["tls_used"] = True
                except Exception as e:
                    out["tls_error"] = "{}: {}".format(type(e).__name__, e)
            else:
                out["tls_note"] = "starttls not advertised, proceeding plain"

        try:
            code, msg = smtp.mail("")
        except smtplib.SMTPServerDisconnected:
            out["status"] = "disconnected"
            return out
        except smtplib.SMTPException as e:
            out["status"] = "smtp_error"
            out["error"] = "mail from: {}".format(e)
            return out

        out["mail_from_code"] = code
        out["mail_from_msg"] = _decode(msg)[:200]
        if code >= 400:
            out["status"] = "mail_from_rejected"
            return out

        try:
            code, msg = smtp.rcpt(target)
            out["rcpt_code"] = code
            out["rcpt_msg"] = _decode(msg)[:300]
            try:
                out["status"] = _interpret_rcpt(code, out["rcpt_msg"])
            except Exception as ie:
                out["status"] = "not_exists" if code == 550 else "rejected"
                out["interpret_error"] = str(ie)
        except smtplib.SMTPRecipientsRefused as e:
            info = e.recipients.get(target) if e.recipients else None
            if info:
                out["rcpt_code"] = info[0]
                out["rcpt_msg"] = _decode(info[1])[:300]
                try:
                    out["status"] = _interpret_rcpt(info[0], out["rcpt_msg"])
                except Exception as ie:
                    out["status"] = "not_exists" if info[0] == 550 else "rejected"
                    out["interpret_error"] = str(ie)
            else:
                out["status"] = "rcpt_refused"
        except smtplib.SMTPServerDisconnected:
            out["status"] = "disconnected"
    except smtplib.SMTPServerDisconnected:
        out["status"] = "disconnected"
    except Exception as e:
        # Never lose an already-captured RCPT result.
        if out.get("rcpt_code"):
            try:
                out["status"] = _interpret_rcpt(out["rcpt_code"], out.get("rcpt_msg", ""))
            except Exception:
                out["status"] = "not_exists" if out["rcpt_code"] == 550 else "rejected"
            out["error"] = "post-rcpt: {}: {}".format(type(e).__name__, e)
        else:
            out["status"] = "error"
            out["error"] = "{}: {}".format(type(e).__name__, e)
    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except Exception:
                try:
                    smtp.close()
                except Exception:
                    pass
    return out


def _probe_all_ports(ip, hostname, ehlo_name, target, priority):
    results = []
    with ThreadPoolExecutor(max_workers=len(SMTP_PORTS)) as ex:
        futures = {
            ex.submit(_probe, ip, ehlo_name, port, tls, target): (port, tls)
            for port, tls in SMTP_PORTS
        }
        for fut in as_completed(futures):
            port, tls = futures[fut]
            try:
                r = fut.result()
            except Exception as e:
                r = {"ip": ip, "hostname": hostname, "port": port, "tls": tls,
                     "status": "error", "connected": False,
                     "error": "{}: {}".format(type(e).__name__, e)}
            r["mx_host"] = hostname
            r["mx_priority"] = priority
            results.append(r)
    results.sort(key=lambda x: PORT_ORDER.get(x["port"], 99))
    return results


def _scan_results(results):
    statuses = [r["status"] for r in results]
    if "exists" in statuses:
        return "exists"
    if "not_exists" in statuses:
        return "not_exists"
    if "rejected" in statuses:
        return "rejected"
    return None


def _final_verdict(attempts):
    if not attempts:
        return "unreachable"
    if not any(a.get("connected") for a in attempts):
        return "unreachable"
    statuses = {a["status"] for a in attempts}
    if "rejected_policy" in statuses or "mail_from_rejected" in statuses:
        return "rejected_policy"
    return "inconclusive"


def check(raw, server=None):
    parsed = _parse_email(raw)
    if not parsed:
        return {"valid": False, "error": "not a valid email address"}

    server = (server or "").strip() or None

    if server:
        mx_info = _resolve_server(server)
        chain = mx_info["chain"]
        if not chain or not any(e["ipv4"] or e["ipv6"] for e in chain):
            return {
                "valid": False, "email": parsed["email"],
                "server": server,
                "error": "could not resolve '{}' to any IP".format(server),
            }
    else:
        mx_info = _resolve_mx_chain(parsed["domain"])
        chain = mx_info["chain"]
        if not chain:
            return {"valid": False, "email": parsed["email"],
                    "error": "no MX / A records"}

    attempts = []
    for entry in chain:
        ehlo_name = _ehlo_name(entry["host"], parsed["domain"])
        for ip in entry["ipv4"] + entry["ipv6"]:
            results = _probe_all_ports(ip, entry["host"], ehlo_name,
                                       parsed["email"], entry["priority"])
            attempts.extend(results)
            verdict = _scan_results(results)
            if verdict:
                result = _result(parsed, mx_info, attempts, verdict)
                if server:
                    result["server"] = server
                return result

    result = _result(parsed, mx_info, attempts, _final_verdict(attempts))
    if server:
        result["server"] = server
    return result


def _result(parsed, mx_info, attempts, verdict):
    return {
        "valid": verdict == "exists",
        "connected": any(a.get("connected") for a in attempts),
        "email": parsed["email"],
        "domain": parsed["domain"],
        "verdict": verdict,
        "mx_source": mx_info["source"],
        "mx_chain": mx_info["chain"],
        "attempts": attempts,
    }
