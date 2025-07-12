import spf
import dkim
import dns.resolver, dns.exception
from pydantic import BaseModel
from dataclasses import dataclass

@dataclass
class AuthResult:
    spf: str
    dkim: str
    dmarc: str

class DMARCError(Exception):
    pass

def _check_spf(domain: str) -> str:
    try:
        result, explanation = spf.check2(i="203.0.113.1", s="test@" + domain, h=domain)
        return result  # pass / fail / neutral / none
    except Exception:
        return "error"

def _check_dkim(domain: str) -> str:
    try:
        records = dns.resolver.resolve(f"selector._domainkey.{domain}", "TXT")
        return "found" if records else "missing"
    except dns.exception.DNSException:
        return "missing"

def _check_dmarc(domain: str) -> str:
    try:
        txt = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        return "present" if txt else "missing"
    except dns.exception.DNSException:
        return "missing"

def check_domain_auth(domain: str) -> dict:
    return {
        "domain": domain,
        "spf": _check_spf(domain),
        "dkim": _check_dkim(domain),
        "dmarc": _check_dmarc(domain),
    }