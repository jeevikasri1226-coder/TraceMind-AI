import io
from datetime import datetime
import pandas as pd
import streamlit as st

st.set_page_config(page_title="TraceMind AI", page_icon="🔎", layout="wide")

REQUIRED_COLUMNS = ["timestamp", "source", "event", "user", "ip", "file", "details"]

st.title("🔎 TraceMind AI")
st.caption("Evidence-linked digital event analysis — prototype")
st.warning(
    "Prototype only: this tool uses simple, transparent rules. A flagged event is not proof of wrongdoing. "
    "Use only data you are authorised to analyse, and remove personal or confidential information."
)

SAMPLE_PATH = Path(__file__).parent / "sample_logs.csv"

def load_events(uploaded_file):
    if uploaded_file is None:
        return pd.read_csv(SAMPLE_PATH)
    name = uploaded_file.name.lower()
    if name.endswith(".csv"):
        return pd.read_csv(uploaded_file)
    if name.endswith(".json"):
        return pd.read_json(uploaded_file)
    raise ValueError("Please upload a CSV or JSON file.")

def normalise_events(df):
    df = df.copy()
    df.columns = [str(c).strip().lower() for c in df.columns]
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(missing))
    df = df[REQUIRED_COLUMNS].copy()
    df["timestamp_original"] = df["timestamp"].astype(str)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df["source"] = df["source"].fillna("unknown").astype(str)
    for col in ["event", "user", "ip", "file", "details"]:
        df[col] = df[col].fillna("").astype(str)
    df["evidence_id"] = [f"EV-{i:04d}" for i in range(1, len(df) + 1)]
    return df

def analyse_events(df):
    df = df.copy()
    df["flagged"] = False
    df["reason"] = ""
    event_lower = df["event"].str.lower()
    detail_lower = df["details"].str.lower()

    failed = event_lower.str.contains(r"failed login|login failed|authentication failure", regex=True)
    success = event_lower.str.contains(r"successful login|login success|logged in", regex=True)
    file_access = event_lower.str.contains(r"file access|file opened|file downloaded|file copied", regex=True)
    network = event_lower.str.contains(r"outbound connection|external connection|network connection", regex=True)

    # Transparent rule 1: multiple failed logins by the same user.
    failed_counts = df.loc[failed & (df["user"] != ""), "user"].value_counts()
    repeated_users = set(failed_counts[failed_counts >= 3].index)
    repeated_failed = failed & df["user"].isin(repeated_users)
    df.loc[repeated_failed, "flagged"] = True
    df.loc[repeated_failed, "reason"] = "Repeated failed logins for this user (3 or more in the uploaded data)."

    # Transparent rule 2: successful login by a user who also had repeated failed logins.
    successful_after_pattern = success & df["user"].isin(repeated_users)
    df.loc[successful_after_pattern, "flagged"] = True
    df.loc[successful_after_pattern, "reason"] = df.loc[successful_after_pattern, "reason"].apply(
        lambda x: (x + " " if x else "") + "Successful login for a user with repeated failures; review the sequence."
    )

    # Transparent rule 3: records explicitly marked unusual/suspicious in details.
    explicit = detail_lower.str.contains(r"\bunusual\b|\bsuspicious\b|\bunauthori[sz]ed\b", regex=True)
    df.loc[explicit, "flagged"] = True
    df.loc[explicit, "reason"] = df.loc[explicit, "reason"].apply(
        lambda x: (x + " " if x else "") + "Details field contains a review keyword."
    )

    # These event types are shown as context, not automatically treated as malicious.
    df["event_type"] = "General"
    df.loc[failed, "event_type"] = "Authentication failure"
    df.loc[success, "event_type"] = "Successful login"
    df.loc[file_access, "event_type"] = "File activity"
    df.loc[network, "event_type"] = "Network activity"
    df["reason"] = df["reason"].str.strip()
    return df.sort_values("timestamp", na_position="last")

with st.sidebar:
    st.header("Evidence input")
    uploaded = st.file_uploader("Upload a CSV or JSON event file", type=["csv", "json"])
    st.markdown("**Required fields**")
    st.code("timestamp, source, event, user, ip, file, details", language="text")
    st.caption("Timestamps should ideally include a timezone, such as +00:00 or Z.")

try:
    raw = load_events(uploaded)
    events = normalise_events(raw)
    results = analyse_events(events)
except Exception as exc:
    st.error(f"Could not process the file: {exc}")
    st.info("Use the sample_logs.csv file in this project as a template.")
    st.stop()

valid_timestamps = results["timestamp"].notna().sum()
flagged = results[results["flagged"]]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events analysed", len(results))
c2.metric("Flagged for review", int(results["flagged"].sum()))
c3.metric("Evidence sources", int(results["source"].nunique()))
c4.metric("Valid timestamps", int(valid_timestamps))

st.subheader("Possible incident timeline")
timeline_cols = ["timestamp", "evidence_id", "source", "event", "user", "ip", "file", "flagged", "reason"]
display = results[timeline_cols].copy()
display["timestamp"] = display["timestamp"].astype(str)
st.dataframe(display, use_container_width=True, hide_index=True)

st.subheader("Evidence-backed findings")
if flagged.empty:
    st.success("No events matched the current prototype rules. This does not guarantee that the data is safe.")
else:
    for _, row in flagged.iterrows():
        with st.expander(f"{row['evidence_id']} — {row['event']}"):
            st.write(f"**Why flagged:** {row['reason']}")
            st.write(f"**Source:** {row['source']}")
            st.write(f"**Timestamp:** {row['timestamp']}")
            st.write(f"**User:** {row['user'] or 'Not provided'}")
            st.write(f"**IP:** {row['ip'] or 'Not provided'}")
            st.write(f"**File:** {row['file'] or 'Not provided'}")
            st.write(f"**Details:** {row['details'] or 'Not provided'}")
            st.caption("Interpretation: a review lead only. Verify against original records and additional evidence.")

st.subheader("Export")
csv_bytes = results.drop(columns=["timestamp_original"], errors="ignore").to_csv(index=False).encode("utf-8")
st.download_button("Download analysed events (CSV)", data=csv_bytes, file_name="tracemind_analysis.csv", mime="text/csv")

report_lines = [
    "# TraceMind AI — Preliminary Evidence Report",
    "",
    f"- Generated: {datetime.now().astimezone().isoformat(timespec='seconds')}",
    f"- Events analysed: {len(results)}",
    f"- Events flagged for review: {int(results['flagged'].sum())}",
    f"- Distinct sources: {int(results['source'].nunique())}",
    "",
    "## Findings",
    "",
]
if flagged.empty:
    report_lines.append("No events matched the current prototype rules. This does not guarantee the data is safe.")
else:
    for _, row in flagged.iterrows():
        report_lines.extend([
            f"### {row['evidence_id']} — {row['event']}",
            f"- Timestamp: {row['timestamp']}",
            f"- Source: {row['source']}",
            f"- User: {row['user'] or 'Not provided'}",
            f"- IP: {row['ip'] or 'Not provided'}",
            f"- File: {row['file'] or 'Not provided'}",
            f"- Reason: {row['reason']}",
            f"- Details: {row['details'] or 'Not provided'}",
            "",
        ])
report_lines.extend([
    "## Limitations",
    "",
    "- This prototype uses simple rules, not a trained AI model.",
    "- Flagged events are leads for human review, not proof of malicious activity.",
    "- Verify all findings against original evidence and relevant context.",
    "- Input quality, missing data, and timestamp differences can affect results.",
])
st.download_button(
    "Download preliminary report (Markdown)",
    data="\n".join(report_lines).encode("utf-8"),
    file_name="tracemind_report.md",
    mime="text/markdown",
)

with st.expander("Prototype rules and limitations"):
    st.markdown("""
    - Flags failed login events when the same non-empty username has at least three failed-login records in the uploaded data.
    - Flags successful logins for usernames that also have repeated failed-login records.
    - Flags details containing words such as `unusual`, `suspicious`, or `unauthorised`.
    - File and network events are included in the timeline but are not automatically labelled malicious.
    - This prototype does not verify IP reputation, prove causality, or determine who performed an action.
    """)
