# TraceMind AI

**An explainable digital-evidence analysis prototype**

TraceMind AI demonstrates how digital event records can be placed into one timeline and how simple, transparent rules can flag events for human review.

## Features

- Upload CSV or JSON event records
- Normalise timestamps and display events chronologically
- Assign evidence IDs to records
- Flag repeated failed logins and selected review keywords
- Show the reason and source record for each flagged event
- Export analysed events as CSV and a preliminary report as Markdown

## Important scope note

This is an early rule-based prototype, not a production forensic tool and not a trained AI system. A flag is not proof of a cybercrime. Verify all findings against original evidence. Use only data you are authorised to analyse. The included sample data is synthetic and uses documentation-only example IP addresses.

## Run locally

1. Install Python 3.10 or newer.
2. Download or clone this repository.
3. Open a terminal in the project folder.
4. Create and activate a virtual environment (recommended):

   **Windows**
   ```bash
   py -m venv .venv
   .venv\Scripts\activate
   ```

   **macOS/Linux**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

5. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
6. Start the app:
   ```bash
   streamlit run app.py
   ```

The app opens in your browser. It loads `sample_logs.csv` by default; use the sidebar to upload your own CSV or JSON.

## Input format

The file must include these columns:

| Column | Meaning |
|---|---|
| `timestamp` | Event date/time; timezone-aware timestamps are recommended |
| `source` | Source system, such as `system_log` or `network_log` |
| `event` | Short event description |
| `user` | Username if available |
| `ip` | IP address if available |
| `file` | File name/path if relevant |
| `details` | Additional context |

Missing values are allowed, but all column names must be present.

## Current prototype rules

- Flags failed-login events when the same username has at least three failed-login records in the uploaded data.
- Flags successful logins for users who also have repeated failed-login records.
- Flags records whose `details` contain terms such as `unusual`, `suspicious`, or `unauthorised`.
- File and network events appear in the timeline but are not automatically considered malicious.

These rules are intentionally simple and may produce false positives or miss suspicious behaviour.

## Project workflow

Evidence input → normalisation → event correlation rules → review flags → timeline → evidence-backed report.

## Future improvements

- Add parsers for more real-world log formats
- Improve cross-source event correlation
- Add configurable detection rules and testing
- Preserve original timestamps and evidence hashes
- Add user authentication, access controls and audit logging before handling sensitive data
- Evaluate detection quality on labelled, authorised datasets

## Team

Add your team members and contributions here.

## References

- [NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final)
- [Streamlit documentation](https://docs.streamlit.io/)
- [Pandas documentation](https://pandas.pydata.org/docs/)
