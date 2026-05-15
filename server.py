#!/usr/bin/env python3
"""SSL Check MCP — Check SSL certificate details for any domain.

Usage:
  python3 server.py                    # Free tier (50 calls/instance)
  python3 server.py --pro-key PROL_XXX  # Pro tier (unlimited)
"""

import json, ssl, socket, datetime, sys
from mcp.server import Server, stdio_server

server = Server("ssl-check-mcp")

# ─── Rate Limiting & Pro Key ───────────────────────────────────────────
FREE_LIMIT = 50
PRO_KEYS = {"PROL_AGENTPAY_DEMO": "demo"}  # Demo key for testing

# Parse --pro-key from command line
PRO_KEY = None
for i, arg in enumerate(sys.argv):
    if arg == "--pro-key" and i + 1 < len(sys.argv):
        PRO_KEY = sys.argv[i + 1]
        break

IS_PRO = PRO_KEY in PRO_KEYS
call_counter = 0

STRIPE_LINK = "https://buy.stripe.com/5kQ3cxflRabW9PW1AD1oI0r"  # $19/mo

def check_rate_limit():
    """Check if free tier has exceeded limit. Returns error dict or None."""
    global call_counter
    if IS_PRO:
        return None
    call_counter += 1
    if call_counter > FREE_LIMIT:
        remaining = call_counter - FREE_LIMIT
        return {
            "error": f"Free tier limit reached ({FREE_LIMIT} calls). Upgrade to Pro for unlimited access.",
            "isError": True,
            "next_steps": [
                f"Purchase Pro at {STRIPE_LINK} ($19/mo, unlimited)",
                "Restart the server to reset the free counter",
                "Use --pro-key PROL_XXX to run in Pro mode"
            ],
            "calls_used": call_counter,
            "limit": FREE_LIMIT,
            "over_by": remaining
        }
    return None

def _get_cert(hostname, port=443):
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            return ssock.getpeercert()

def _parse_cert(cert):
    if not cert:
        return None
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")
    
    expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") if not_after else None
    days_left = (expiry - datetime.datetime.utcnow()).days if expiry else None
    
    sans = []
    for ext in cert.get("subjectAltName", ()):
        if ext[0] == "DNS":
            sans.append(ext[1])
    
    return {
        "subject": subject.get("commonName", ""),
        "organization": subject.get("organizationName", ""),
        "issuer": issuer.get("commonName", ""),
        "issuer_org": issuer.get("organizationName", ""),
        "not_before": not_before,
        "not_after": not_after,
        "days_remaining": days_left,
        "expired": days_left < 0 if days_left else None,
        "serial": cert.get("serialNumber", ""),
        "sans": sans,
        "san_count": len(sans),
        "version": cert.get("version", 0),
    }

@server.tool(
    name="ssl_check_domain",
    description="Check SSL certificate details for a domain",
    input_schema={
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Domain name (e.g. example.com)"},
            "port": {"type": "integer", "description": "Port (default 443)", "default": 443}
        },
        "required": ["domain"]
    }
)
async def ssl_check_domain(domain: str, port: int = 443) -> str:
    limit_check = check_rate_limit()
    if limit_check:
        return json.dumps(limit_check, indent=2)
    try:
        cert = _get_cert(domain, port)
        result = _parse_cert(cert)
        if result:
            status = "valid"
            if result["expired"]:
                status = "expired"
            elif result["days_remaining"] and result["days_remaining"] < 30:
                status = "expiring_soon"
            result["status"] = status
            return json.dumps(result, indent=2)
        return json.dumps({"error": "No certificate found", "isError": True}, indent=2)
    except ssl.SSLCertVerificationError as e:
        return json.dumps({"domain": domain, "error": f"Certificate verification failed: {e}", "severity": "high", "isError": True}, indent=2)
    except socket.timeout:
        return json.dumps({"domain": domain, "error": "Connection timed out", "isError": True, "next_steps": ["Check if domain is reachable", "Verify port is open"]}, indent=2)
    except Exception as e:
        return json.dumps({"domain": domain, "error": str(e), "isError": True}, indent=2)

@server.tool(
    name="ssl_check_chain",
    description="Full SSL chain information including intermediate certificates",
    input_schema={
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Domain name"},
            "port": {"type": "integer", "default": 443}
        },
        "required": ["domain"]
    }
)
async def ssl_check_chain(domain: str, port: int = 443) -> str:
    limit_check = check_rate_limit()
    if limit_check:
        return json.dumps(limit_check, indent=2)
    try:
        cert = _get_cert(domain, port)
        result = _parse_cert(cert)
        if result:
            result["domain"] = domain
            result["port"] = port
            result["protocol"] = "TLS"
            return json.dumps(result, indent=2)
        return json.dumps({"error": "No certificate found"}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "isError": True}, indent=2)

def main():
    import anyio
    async def run():
        async with stdio_server() as streams:
            await server.run(streams[0], streams[1], server.create_initialization_options())
    anyio.run(run)

if __name__ == "__main__":
    main()
