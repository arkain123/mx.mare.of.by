import checkdmarc


def check(domain: str) -> dict:
    try:
        result = checkdmarc.check_spf(domain)
    except checkdmarc.SPFRecordNotFound:
        return {"valid": False, "domain": domain, "error": "No SPF record found"}
    except checkdmarc.SPFError as e:
        return {"valid": False, "domain": domain, "error": f"SPF error: {e}"}
    except Exception as e:
        return {"valid": False, "domain": domain, "error": str(e)}

    return {
        "valid": bool(result.get("valid")),
        "domain": domain,
        "record": result.get("record"),
        "version": result.get("version"),
        "redirect": result.get("redirect"),
        "exp": result.get("exp"),
        "dns_lookups": result.get("dns_lookups", 0),
        "warnings": result.get("warnings", []),
        "parsed": result.get("parsed"),
        "parsed_all": result.get("parsed_all"),
    }
