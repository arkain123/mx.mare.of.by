import checkdmarc


def check(domain: str) -> dict:
    try:
        result = checkdmarc.check_dmarc(domain)
    except checkdmarc.DMARCRecordNotFound:
        return {"valid": False, "domain": domain, "error": "No DMARC record found"}
    except checkdmarc.DMARCError as e:
        return {"valid": False, "domain": domain, "error": f"DMARC error: {e}"}
    except Exception as e:
        return {"valid": False, "domain": domain, "error": str(e)}

    tags = result.get("tags") or {}
    policy = tags.get("p") if isinstance(tags, dict) else None
    return {
        "valid": bool(result.get("valid")),
        "domain": domain,
        "record": result.get("record"),
        "location": result.get("location"),
        "policy": policy,
        "tags": tags,
        "warnings": result.get("warnings", []),
    }
