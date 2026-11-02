# SIEM-Style Security Alert Triage (Synthetic Lab)

I built an offline Python lab to practice sorting security events, correlating failed logins with later successes, identifying endpoint and privilege-change alerts, and writing follow-up recommendations. This is **not Wazuh, Splunk, Sentinel or production SIEM experience**.

The demo analyzes 10 fabricated events and produces four alerts: repeated SSH failures, SSH failures followed by success, a simulated malware detection, and a privilege change. Every finding includes its rule, severity, host, evidence IDs, and recommended next action.

Run from this folder with Python 3.10+:

```bash
python -m unittest discover -s tests -v
python -m src.triage
```

Outputs: `reports/triage_summary.md` and `reports/alerts.json`. No third-party dependencies.

Limitations: batch analysis only; no live collection, real SIEM, true endpoint telemetry, time-window correlation, production incident management, or threat-intelligence integration. All events are synthetic.