"""Retrieval over the threat-report set (TF-IDF + IOC exact-match boost).

Each report is split into sections (chunks). A query is scored against every chunk with
cosine similarity over TF-IDF vectors; a document's score is its best chunk score plus a
boost for every indicator of compromise (IOC) from the report that appears verbatim in
the query. This keeps the retriever dependency-free (numpy only) and fully reproducible.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

_TOKEN = re.compile(r"[a-z0-9][a-z0-9_\-\.]*[a-z0-9]|[a-z0-9]")
_STOP = set(
    "a an and are as at be by for from has have in into is it its of on or that the then "
    "this to was were with which who within over after before any all also can most often "
    "such than their them they these very".split()
)
IOC_BOOST = 0.35


def tokenize(text: str) -> list[str]:
    toks = [t for t in _TOKEN.findall(text.lower()) if t not in _STOP]
    out = []
    for t in toks:
        out.append(t)
        # also index sub-parts of hyphen/dot words (e.g. "high-entropy" -> "high", "entropy")
        parts = re.split(r"[\-\._]", t)
        if len(parts) > 1:
            out.extend(p for p in parts if p and p not in _STOP)
    # crude stemming so "encrypted"/"encryption" and "phishing"/"phish" meet
    return [_stem(t) for t in out]


def _ioc_in(ioc: str, text_lower: str) -> bool:
    """Exact IOC match on token boundaries, so 1.2.3.4 does not match inside 11.2.3.45.

    Domain IOCs may be preceded by a dot so they also match subdomains
    (exfil-cdn.example matches d4t4.exfil-cdn.example); IP IOCs may not.
    """
    is_ip = re.fullmatch(r"[\d.]+", ioc) is not None
    before = r"(?<![\w.\-])" if is_ip else r"(?<![\w\-])"
    pattern = before + re.escape(ioc.lower()) + r"(?![\w\-]|\.\w)"
    return re.search(pattern, text_lower) is not None


def _stem(t: str) -> str:
    for suf in ("ation", "ing", "ed", "es", "s"):
        if len(t) > len(suf) + 3 and t.endswith(suf):
            return t[: -len(suf)]
    return t


@dataclass
class ReportDoc:
    doc_id: str
    title: str
    base_severity: int
    iocs: list[str]
    sections: dict[str, str]
    path: str
    containment: list[dict] = field(default_factory=list)


@dataclass
class Chunk:
    doc_id: str
    section: str
    text: str


def parse_report(path: Path) -> ReportDoc:
    text = path.read_text(encoding="utf-8")
    title_line = next(line for line in text.splitlines() if line.startswith("# "))
    doc_id, _, title = title_line[2:].partition(":")
    sev = re.search(r"\*\*Base severity:\*\*\s*(\d)", text)
    ioc_line = re.search(r"\*\*IOCs:\*\*\s*(.+)", text)
    iocs = []
    if ioc_line and "none" not in ioc_line.group(1).lower():
        iocs = [i.strip() for i in ioc_line.group(1).split(",") if i.strip()]

    sections: dict[str, str] = {}
    current = None
    for line in text.splitlines():
        if line.startswith("## "):
            current = line[3:].strip()
            sections[current] = ""
        elif current:
            sections[current] += line + "\n"

    containment = []
    for line in sections.get("Recommended Containment", "").splitlines():
        m = re.match(r"\s*(\d+)\.\s*\[(\w+)\]\s*(\w+)\s*\|\s*(\w+)\s*\|\s*([^|]+?)\s*(?:\|\s*(.+))?$", line)
        if not m:
            continue
        opts = {}
        if m.group(6):
            for kv in m.group(6).split(","):
                k, _, v = kv.partition("=")
                opts[k.strip()] = v.strip()
        containment.append({
            "num": int(m.group(1)), "phase": m.group(2), "action": m.group(3),
            "target_type": m.group(4), "template": m.group(5), **opts,
        })

    return ReportDoc(
        doc_id=doc_id.strip(), title=title.strip(), base_severity=int(sev.group(1)) if sev else 2,
        iocs=iocs, sections=sections, path=str(path), containment=containment,
    )


class ThreatReportIndex:
    def __init__(self, report_dir: Path):
        self.docs: dict[str, ReportDoc] = {}
        self.chunks: list[Chunk] = []
        for p in sorted(Path(report_dir).glob("*.md")):
            doc = parse_report(p)
            self.docs[doc.doc_id] = doc
            # header chunk (title + IOCs) plus each descriptive section
            self.chunks.append(Chunk(doc.doc_id, "Title", f"{doc.title}. IOCs: {' '.join(doc.iocs)}"))
            for name, body in doc.sections.items():
                self.chunks.append(Chunk(doc.doc_id, name, f"{doc.title}. {body}"))
        self._build()

    def _build(self) -> None:
        tokenized = [tokenize(c.text) for c in self.chunks]
        vocab = sorted({t for toks in tokenized for t in toks})
        self.vocab = {t: i for i, t in enumerate(vocab)}
        n = len(self.chunks)
        df = Counter(t for toks in tokenized for t in set(toks))
        self.idf = np.array([math.log((1 + n) / (1 + df[t])) + 1 for t in vocab])
        self.matrix = np.vstack([self._vec(toks) for toks in tokenized])

    def _vec(self, toks: list[str]) -> np.ndarray:
        v = np.zeros(len(self.vocab))
        for t, c in Counter(toks).items():
            if t in self.vocab:
                v[self.vocab[t]] = (1 + math.log(c)) * self.idf[self.vocab[t]]
        norm = np.linalg.norm(v)
        return v / norm if norm else v

    def search(self, query: str, top_k: int = 3) -> list[dict]:
        q = self._vec(tokenize(query))
        sims = self.matrix @ q
        best: dict[str, tuple[float, str]] = {}
        for chunk, s in zip(self.chunks, sims):
            if chunk.doc_id not in best or s > best[chunk.doc_id][0]:
                best[chunk.doc_id] = (float(s), chunk.section)

        q_lower = query.lower()
        results = []
        for doc_id, (score, section) in best.items():
            doc = self.docs[doc_id]
            ioc_hits = [i for i in doc.iocs if _ioc_in(i, q_lower)]
            results.append({
                "doc_id": doc_id,
                "title": doc.title,
                "score": round(score + IOC_BOOST * len(ioc_hits), 4),
                "text_score": round(score, 4),
                "matched_section": section,
                "ioc_hits": ioc_hits,
                "base_severity": doc.base_severity,
            })
        results.sort(key=lambda r: r["score"], reverse=True)
        return results[:top_k]
