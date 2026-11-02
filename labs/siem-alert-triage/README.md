# Security Alert Triage — Offline Python Lab

I used fabricated authentication, endpoint, and account-change events to practice the first part of an alert investigation: deciding what deserves attention, preserving the event IDs, and documenting a next step.

This is a small **Python correlation exercise**, not a live SIEM deployment. It does not use Wazuh, Splunk, or Sentinel.

## What the script checks

The input is ten events in [`data/events.jsonl`](data/events.jsonl). The script groups events by host and source IP, then applies four simple rules:

| Rule | Condition | Severity |
| --- | --- | --- |
| AUTH-001 | At least three SSH failures from the same host/IP pair | Medium |
| AUTH-002 | At least three failures and a success from the same host/IP pair | High |
| ENDPOINT-001 | An event labeled `malware_detected` | High |
| IAM-001 | An event labeled `privilege_change` | Medium |

The generated report includes the rule, host, source IP, matching event IDs, and suggested investigation step. The example data produces four alerts.

**A limitation I noticed:** AUTH-002 does not establish that the successful login occurred *after* the failures. The events have no timestamps, so this is only a co-occurrence check. I would add timestamps and an ordered time window before using that label in a more realistic detector. Likewise, an endpoint event label is not proof of malware.

## Running the exercise

From this folder, using Python 3.10 or later:

```bash
python -m unittest discover -s tests -v
python -m src.triage
```

The eight tests cover empty input, normal logins, threshold detection, an SSH failure/success combination, endpoint and privilege-change alerts, attached evidence IDs, and source-IP separation.

The script writes `reports/alerts.json` and `reports/triage_summary.md`. All addresses use documentation IP ranges or placeholder values.

## What I would improve

- Add timestamps and sliding-window correlation to reduce false positives.
- Keep each alert's original raw event so an analyst can review context.
- Include analyst disposition and follow-up status.
- Feed events from a real lab collector only after handling test data and permissions safely.

I kept this exercise separate from my original SSH log-triage tool so the differences between parsing logs and correlating simplified events remain clear.
