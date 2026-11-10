"""Alert Parser Agent: raw vendor alert -> structured IncidentRecord.

Handles JSON alerts from different products (EDR, mail gateway, CloudTrail, DLP, NDR, DNS
analytics, AV) whose field names differ, and plain syslog lines. Field aliases normalise
the known fields; regexes pull indicators (IPs, hashes, domains, access keys) out of the
full alert text so nothing is lost when a product uses an unexpected field name.

Outcome signal ("confirmed" / "blocked" / "unknown") is security-conservative: evidence
that the attack succeeded wins over evidence that parts of it were blocked, and
negated phrases ("was not executed") are ignored.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from ..llm import fence
from ..models import IncidentRecord
from .base import BaseAgent, clean_str

HOST_FIELDS = ["device_name", "src_host", "hostname", "host", "dest_host", "computer"]
USER_FIELDS = ["user", "username", "recipient", "account_name"]
TITLE_FIELDS = ["title", "rule_name", "eventName", "signature"]
DETAIL_FIELDS = ["details", "description", "message"]
FILE_FIELDS = ["file", "process", "file_path"]
DOMAIN_FIELDS = ["query_domain", "dest_domain", "domain", "url"]
SENDER_FIELDS = ["sender", "from"]

INTERNAL_DOMAINS = {"corp.example"}
# Last labels that are file extensions, not top-level domains.
FILE_EXTENSIONS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jar", "py", "sh", "php", "asp", "aspx",
    "jsp", "txt", "log", "csv", "json", "xml", "html", "htm", "doc", "docx", "xls", "xlsx", "pdf",
    "zip", "rar", "7z", "gz", "tar", "iso", "img", "msi", "lnk", "tmp", "dat", "bin", "cvault",
}
# Common two-level public suffixes so evil.co.uk -> evil.co.uk (not co.uk).
TWO_LEVEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.in", "co.jp",
                      "com.br", "com.cn", "co.nz", "co.za", "com.mx", "com.tr"}
PRIVATE_NETS = [ipaddress.ip_network(n) for n in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]

RE_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{12,}\b")
RE_ACCOUNT = re.compile(r"\b\d{12}\b")
RE_DOMAIN = re.compile(r"(?<![\w@.\-])((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w\-]|\.\w)", re.I)
RE_SYSLOG = re.compile(r"^\w{3}\s+\d+\s+[\d:]+\s+(\S+)\s+([\w\-]+)(?:\[\d+\])?:\s*(.*)$", re.S)

SUCCESS_PATTERNS = [r"encrypted", r"submitted credentials", r"succeeded", r"executed", r"exfiltrat\w*",
                    r"launched", r"compromised", r"[1-9][\d,]* successful"]
BLOCKED_PATTERNS = [r"blocked", r"denied", r"drop", r"failed", r"0 successful", r"prevented"]
NEGATIONS = re.compile(r"\b(?:not|no|never|without|un)\s*$")


def _matches(patterns: list[str], text: str) -> bool:
    for p in patterns:
        for m in re.finditer(rf"\b{p}\b", text):
            if not NEGATIONS.search(text[max(0, m.start() - 12):m.start()]):
                return True
    return False


def _first(d: dict, keys: list[str]) -> Any:
    for k in keys:
        if d.get(k):
            return d[k]
    return None


def registered_domain(fqdn: str) -> str:
    parts = fqdn.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else fqdn.lower()


def extract_domains(text: str) -> list[str]:
    out = []
    for m in RE_DOMAIN.finditer(text):
        d = m.group(1).lower()
        if d.rsplit(".", 1)[-1] in FILE_EXTENSIONS:
            continue
        out.append(registered_domain(d))
    return out


def is_internal_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in PRIVATE_NETS)


LLM_INSTRUCTIONS = """You are the Alert Parser agent in a security operations centre.
Read one raw security alert and extract its indicators. Return a JSON object with exactly these keys:
{"summary": "one plain sentence describing what happened",
 "hosts": [], "users": [], "ips": [], "domains": [], "hashes": [], "files": [], "email_senders": [],
 "signal": "confirmed | blocked | unknown",
 "signal_evidence": "the exact words from the alert that justify the signal"}
Rules: only list values that appear literally in the alert. "confirmed" means the attack
succeeded, "blocked" means it was stopped or failed, "unknown" means the alert does not say."""

LIST_FIELDS = ("hosts", "users", "ips", "domains", "hashes", "files", "email_senders")


class AlertParserAgent(BaseAgent):
    name = "AlertParserAgent"

    async def run(self, **_: Any) -> IncidentRecord:
        raw = self.timeline.latest("alert_received")["raw"]
        record = self.parse(raw)
        if self.llm is not None:
            raw_text = json.dumps(raw) if isinstance(raw, dict) else str(raw)
            out = await self.think("entity_extraction", LLM_INSTRUCTIONS, fence(raw_text))
            if out:
                self.merge_llm(record, out, raw_text)
        self.log("incident_record_created", record.to_dict())
        return record

    def merge_llm(self, record: IncidentRecord, out: dict, raw_text: str) -> None:
        """Add LLM-found entities only if they are verifiable in the raw alert text."""
        haystack = raw_text.lower().replace("\\\\", "\\")
        added: dict[str, list[str]] = {}
        rejected: list[str] = []

        def verbatim(v: str) -> bool:
            return len(v) >= 2 and v.lower() in haystack

        for fieldname in LIST_FIELDS:
            values = out.get(fieldname)
            if not isinstance(values, list):
                continue
            for v in values[:20]:
                if not isinstance(v, str) or not v.strip():
                    continue
                v = v.strip()
                if not verbatim(v):
                    rejected.append(f"{fieldname}:{v[:60]}")
                    continue
                norm = None
                if fieldname == "ips":
                    try:
                        ipaddress.ip_address(v)
                        norm = v
                    except ValueError:
                        rejected.append(f"ips:{v[:60]}")
                        continue
                elif fieldname == "domains":
                    found = extract_domains(v)
                    norm = found[0] if found and found[0] not in INTERNAL_DOMAINS else None
                elif fieldname == "hashes":
                    norm = v.lower() if RE_SHA256.fullmatch(v) else None
                elif fieldname == "hosts":
                    norm = v.upper() if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9\-_.]{1,62}", v) else None
                elif fieldname == "users":
                    norm = v.split("@")[0].lower() if re.fullmatch(r"[\w.\-@]{2,64}", v) else None
                elif fieldname == "files":
                    norm = v if ("\\" in v or "/" in v) else None
                elif fieldname == "email_senders":
                    norm = v.lower() if "@" in v else None
                current = getattr(record, fieldname)
                if norm and norm not in current:
                    current.append(norm)
                    added.setdefault(fieldname, []).append(norm)
                    if fieldname == "ips":
                        (record.internal_ips if is_internal_ip(norm) else record.external_ips).append(norm)

        record.summary = clean_str(out.get("summary"), 300)
        signal = out.get("signal") if out.get("signal") in ("confirmed", "blocked", "unknown") else None
        evidence = clean_str(out.get("signal_evidence"), 300)
        if signal:
            record.llm_signal = {
                "signal": signal,
                "evidence": evidence,
                "evidence_verified": bool(evidence) and evidence.lower() in haystack,
                "agrees_with_rules": signal == record.status_signal,
            }
        record.llm_added = {"added": added, "rejected_unverifiable": rejected[:20]}

    def parse(self, raw: Any) -> IncidentRecord:
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    raw = parsed
            except json.JSONDecodeError:
                pass

        fields: dict[str, Any] = {}
        if isinstance(raw, dict):
            fields = raw
            text = " ".join(str(v) for v in raw.values())
            source = str(raw.get("source", "unknown"))
        else:
            text = str(raw)
            source = "syslog"
            m = RE_SYSLOG.match(text.strip())
            if m:
                fields = {"hostname": m.group(1), "process": m.group(2), "details": m.group(3)}
                source = f"syslog:{m.group(2)}"

        details = str(_first(fields, DETAIL_FIELDS) or text)
        title = _first(fields, TITLE_FIELDS)
        if not title:
            # syslog / free text: use the last clause as a short title
            title = details.split(";")[-1].strip()[:120].capitalize() or "Untitled alert"

        host = _first(fields, HOST_FIELDS)
        hosts = [str(host).upper()] if host else []
        user = _first(fields, USER_FIELDS)
        users = [str(user).split("@")[0].lower()] if user else []

        ips, internal, external = [], [], []
        for candidate in dict.fromkeys(RE_IP.findall(text)):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue                       # e.g. 999.1.1.1
            ips.append(candidate)
            (internal if is_internal_ip(candidate) else external).append(candidate)

        domains: list[str] = []
        for k in DOMAIN_FIELDS:
            if fields.get(k):
                domains += extract_domains(str(fields[k]))
        sender = _first(fields, SENDER_FIELDS)
        senders = [str(sender).lower()] if sender else []
        for s in senders:
            if "@" in s:
                domains += extract_domains(s.split("@", 1)[1])
        domains += extract_domains(details)
        domains = [d for d in dict.fromkeys(domains) if d not in INTERNAL_DOMAINS]

        files = [str(fields[k]) for k in FILE_FIELDS
                 if fields.get(k) and ("\\" in str(fields[k]) or "/" in str(fields[k]))]
        cloud_keys = list(dict.fromkeys(RE_AWS_KEY.findall(text)))
        accounts = [str(fields["account"])] if fields.get("account") else list(dict.fromkeys(RE_ACCOUNT.findall(text)))

        low = text.lower()
        if _matches(SUCCESS_PATTERNS, low):
            status = "confirmed"
        elif _matches(BLOCKED_PATTERNS, low):
            status = "blocked"
        else:
            status = "unknown"

        vendor = fields.get("vendor_severity")
        return IncidentRecord(
            incident_id=self.timeline.incident_id,
            source=source,
            title=str(title),
            description=details,
            vendor_severity=str(vendor) if vendor else None,
            status_signal=status,
            hosts=hosts, users=users, ips=ips, external_ips=external, internal_ips=internal,
            domains=domains, hashes=list(dict.fromkeys(h.lower() for h in RE_SHA256.findall(text))),
            files=files, email_senders=senders, cloud_keys=cloud_keys, cloud_accounts=accounts,
        )
