"""Summit Risk: Vendor Risk Agent demo.

Upload a ZIP containing vendors.csv and PDF or text documents. The agent scans every file
for injection phrases first, scores vendor names against a hard-coded demo
sanctions list (Levenshtein exact/fuzzy match), and queues every vendor for a
human decision. Nothing is ever blocked or cleared automatically.
The sanctions list below is a demo list, not a real sanctions source.
"""
import io
import re
import unicodedata
import zipfile
from datetime import datetime

import pandas as pd
import streamlit as st

SANCTIONED_NAMES = [                                          # mock list only, not a real source
    "Acme Corp", "Global Trading",
    "Acme Trading Ltd", "Global Shipping Co", "Tech Innovations LLC", "North Star Mining",
    "Al Baraka Exchange", "Mekong Timber Group", "Baltic Marine Group", "Ironclad Security",
    "Quantum Chips Ltd", "Gulf Finance House", "Vostok Aviation", "Persian Petrochem",
]
HIGH_RISK_COUNTRIES = ["Iran", "North Korea", "Syria"]      # demo list only
FUZZY_THRESHOLD = 0.85
MAX_FILES = 200
MAX_PDF_BYTES = 5_000_000
REQUIRED_COLUMNS = ["name", "country", "registration_number"]

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+|any\s+|the\s+)*(previous|prior|above|earlier)\s+(instructions|rules|prompts?)",
    r"disregard\s+(all\s+|any\s+|the\s+)*(previous|prior|above|earlier)",
    r"(reveal|show|print)\s+(the\s+|your\s+)?system\s+prompt",
    r"\bsystem\s+prompt\b",
    r"rank\s+me\s+(first|number\s+one|#1|at\s+the\s+top)",
    r"you\s+are\s+now\s+(a|an|the)\b",
    r"override\s+(the\s+)?(rules|instructions|safety)",
    r"note\s+to\s+(the\s+)?(ai|assistant|model|llm)\b",
]


def is_injection(text: str) -> bool:
    t = re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text).lower())
    return any(re.search(p, t) for p in INJECTION_PATTERNS)


# ---------------------------------------------------------------------------
# Levenshtein matching (pure Python, no extra package)
# ---------------------------------------------------------------------------
def norm_name(s: str) -> str:
    s = unicodedata.normalize("NFKC", str(s)).casefold()
    s = re.sub(r"[^\w\s]", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def ratio(a: str, b: str) -> float:
    longest = max(len(a), len(b))
    return 1.0 if longest == 0 else 1 - levenshtein(a, b) / longest


LEGAL_SUFFIXES = {"co", "llc", "ltd", "inc", "corp", "corporation", "company", "trading", "limited", "fze", "fzco", "group"}


def strip_suffixes(n: str) -> str:
    words = n.split()
    while len(words) > 1 and words[-1] in LEGAL_SUFFIXES:
        words.pop()
    return " ".join(words)


def match_name(name: str):
    """Return (score, reason). 100 exact, 75 fuzzy or suffix variant, 0 none."""
    n = norm_name(name)
    best, best_ratio = None, 0.0
    for s in SANCTIONED_NAMES:
        ns = norm_name(s)
        r = ratio(n, ns)
        if r == 1.0:
            return 100, f"Exact sanctions match: {s}"
        if n != ns and (n.startswith(ns + " ") or ns.startswith(n + " ")) \
                and strip_suffixes(n) == strip_suffixes(ns):
            return 75, f"Fuzzy sanctions match: {s} (same name plus a company suffix)"
        if r > best_ratio:
            best, best_ratio = s, r
    if best_ratio >= FUZZY_THRESHOLD:
        return 75, f"Fuzzy sanctions match: {best} ({best_ratio:.0%} similar)"
    return 0, ""


# ---------------------------------------------------------------------------
# ZIP processing
# ---------------------------------------------------------------------------
def read_doc_text(name: str, data: bytes) -> str:
    if name.lower().endswith(".txt"):
        return data.decode("utf-8", errors="ignore").strip()
    return read_pdf_text(data)


def read_pdf_text(data: bytes) -> str:
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        return "\n".join((p.extract_text() or "") for p in reader.pages).strip()
    except Exception:
        return ""


def process_zip(data: bytes) -> dict:
    out = {"error": None, "files": [], "vendors": []}
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        out["error"] = "That file is not a valid ZIP."
        return out
    names = [n for n in z.namelist() if not n.endswith("/")]
    if len(names) > MAX_FILES:
        out["error"] = f"Too many files in the ZIP (limit {MAX_FILES})."
        return out
    csvs = [n for n in names if n.split("/")[-1].lower() == "vendors.csv"]
    if not csvs:
        out["error"] = "No vendors.csv found in the ZIP."
        return out
    try:
        df = pd.read_csv(io.BytesIO(z.read(csvs[0])), dtype=str).fillna("")
    except Exception:
        out["error"] = "vendors.csv could not be read."
        return out
    df.columns = df.columns.str.strip().str.lower()
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        out["error"] = "vendors.csv is missing column(s): " + ", ".join(missing)
        return out

    # 1. Quarantine scan on every PDF and text file, before anything else uses the text
    for n in names:
        if not n.lower().endswith((".pdf", ".txt")):
            continue
        base = n.split("/")[-1]
        if z.getinfo(n).file_size > MAX_PDF_BYTES:
            out["files"].append({"file": base, "status": "Skipped (too large)"})
            continue
        text = read_doc_text(n, z.read(n))
        if not text:
            out["files"].append({"file": base, "status": "Unreadable (no text; needs OCR)"})
        elif is_injection(text):
            out["files"].append({"file": base, "status": "Quarantined"})
        else:
            out["files"].append({"file": base, "status": "Clean"})

    # 2. Score each vendor from the CSV fields only (never from PDF text)
    for _, row in df.iterrows():
        name, country, reg = row["name"].strip(), row["country"].strip(), row["registration_number"].strip()
        score, reasons = 0, []
        csv_injection = any(is_injection(str(c)) for c in row.values)
        s, why = match_name(name)
        if s:
            score, reasons = s, [why]
        elif country in HIGH_RISK_COUNTRIES:
            score, reasons = 25, [f"High-risk country: {country}"]
        docs = [f for f in out["files"] if reg and reg in f["file"]]
        quarantined = [f["file"] for f in docs if f["status"] == "Quarantined"]
        unreadable = [f["file"] for f in docs if f["status"].startswith(("Unreadable", "Skipped"))]
        if csv_injection:
            reasons.append("Injection text found in the CSV row")
        if quarantined:
            reasons.append("Document quarantined: " + ", ".join(quarantined))
        if unreadable:
            reasons.append("Document unreadable, needs manual check: " + ", ".join(unreadable))
        if quarantined or csv_injection:
            status = "Quarantined: File Malicious"
        elif score >= 75:
            status = "High Risk"
        elif score == 25 or unreadable:
            status = "Needs Review"
        else:
            status = "Low Risk: no flags"
        out["vendors"].append({
            "Vendor Name": name, "Country": country, "Registration": reg, "Score": score,
            "Documents": len(docs), "Reason": "; ".join(reasons) or "No flags", "Status": status})
    return out


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
def log(event: str, subject: str = "", detail: str = ""):
    st.session_state.audit.append({"Time": datetime.utcnow().strftime("%H:%M:%S") + " UTC",
                                   "Event": event, "Subject": subject, "Detail": detail})


def log_once(key, *args):
    if key not in st.session_state.logged:
        st.session_state.logged.add(key)
        log(*args)


def main():
    st.set_page_config(page_title="Summit Risk Agent", layout="wide")
    for k, v in (("audit", []), ("logged", set()), ("decisions", {})):
        if k not in st.session_state:
            st.session_state[k] = v
    st.title("🛡️ Summit Risk: Vendor Risk Agent")
    st.markdown("**Demo: upload a ZIP with `vendors.csv` and PDF or text documents.**")
    st.sidebar.header("Agent Rules")
    st.sidebar.info("1. Every PDF and text file is scanned for injection before it is used.\n"
                    "2. Scores come from the CSV, never from document text.\n"
                    "3. Names are matched with Levenshtein: exact = 100, fuzzy = 75.\n"
                    "4. No vendor is blocked or cleared automatically. A person decides.")
    st.sidebar.caption("The sanctions list in this demo is a hard-coded sample, not a real source.")

    up = st.file_uploader("Upload vendor ZIP", type=["zip"])
    if up:
        data = up.getvalue()
        key = (up.name, len(data))
        res = process_zip(data)
        if res["error"]:
            st.error(res["error"])
        else:
            st.write("### 1. Pre-flight check")
            q = [f for f in res["files"] if f["status"] == "Quarantined"]
            qcsv = [v["Vendor Name"][:40] for v in res["vendors"] if "CSV row" in v["Reason"]]
            st.success(f"{len(res['vendors'])} vendors in vendors.csv. {len(res['files'])} document(s) scanned.")
            if res["files"]:
                st.dataframe(pd.DataFrame(res["files"]), use_container_width=True, hide_index=True)
            if q or qcsv:
                st.error("🚨 Quarantine Alert: Malicious files detected: "
                         + ", ".join([f["file"] for f in q] + [f"CSV row '{n}'" for n in qcsv])
                         + ". Nothing flagged was read further. Quarantined vendors cannot be approved until a person resolves them.")
            for f in res["files"]:
                if f["status"] != "Clean":
                    log_once(key + (f["file"],), f"File {f['status'].split(' (')[0].lower()}", f["file"], "")
            for vi, v in enumerate(res["vendors"]):
                if v["Status"] != "Low Risk: no flags":
                    log_once(key + (vi, "flag"),
                             "Vendor flagged: " + v["Status"], v["Vendor Name"], v["Reason"])

            st.write("### 2. Screening results")
            st.dataframe(pd.DataFrame(res["vendors"]), use_container_width=True, hide_index=True)

            st.write("### 3. Human approval queue")
            st.info("The agent prepares. The human decides. Nothing is cleared or blocked until you act.")
            tier = {"Quarantined": 0, "High Risk": 1, "Needs Review": 2}
            order = sorted(enumerate(res["vendors"]),
                           key=lambda p: (tier.get(p[1]["Status"].split(":")[0], 3), p[0]))
            for i, v in order:
                vid = (key, i)
                done = st.session_state.decisions.get(vid)
                label = f"{v['Vendor Name']} ({v['Status']})" + (f" | decision: {done}" if done else "")
                with st.expander(label):
                    st.write(f"**Score:** {v['Score']} | **Reason:** {v['Reason']}")
                    reason = st.text_input("Reason (required to dismiss)", key=f"why_{i}")
                    c1, c2, c3 = st.columns(3)
                    if v["Status"].startswith("Quarantined"):
                        c1.caption("🔒 Cannot be approved until the file is resolved.")
                        if c1.button("🚫 Confirm Malicious", key=f"cm_{i}"):
                            st.session_state.decisions[vid] = "Blocked (confirmed malicious)"
                            log("Quarantine confirmed malicious by reviewer", v["Vendor Name"], reason)
                            st.rerun()
                        if c1.button("🔓 Release file", key=f"rl_{i}"):
                            if reason.strip():
                                st.session_state.decisions[vid] = "Quarantine released"
                                log("Quarantine released by reviewer", v["Vendor Name"], reason)
                                st.rerun()
                            else:
                                st.warning("Enter a reason to release.")
                    elif c1.button("✅ Approve", key=f"ap_{i}"):
                        st.session_state.decisions[vid] = "Approved"
                        log("Vendor approved by reviewer", v["Vendor Name"], reason)
                        st.rerun()
                    if c2.button("❌ Dismiss", key=f"di_{i}"):
                        if reason.strip():
                            st.session_state.decisions[vid] = "Dismissed"
                            log("Flag dismissed by reviewer", v["Vendor Name"], reason)
                            st.rerun()
                        else:
                            st.warning("Enter a reason to dismiss.")
                    if c3.button("⚠️ Escalate", key=f"es_{i}"):
                        st.session_state.decisions[vid] = "Escalated"
                        log("Vendor escalated by reviewer", v["Vendor Name"], reason)
                        st.rerun()
    else:
        st.info("Upload a ZIP to start. Files are read in memory and not stored.")

    st.write("---")
    st.write("### 4. Audit log")
    if st.session_state.audit:
        st.dataframe(pd.DataFrame(st.session_state.audit), use_container_width=True, hide_index=True)
    else:
        st.info("No events yet.")


if __name__ == "__main__":
    main()
