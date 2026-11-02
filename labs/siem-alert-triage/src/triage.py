"""Offline correlation of synthetic security events; not a real SIEM."""
import json
from pathlib import Path
from collections import defaultdict

def analyze(events):
    groups = defaultdict(list)
    for event in events:
        groups[(event.get("host","unknown"),event.get("src_ip","none"))].append(event)
    alerts=[]
    for (host,ip), items in sorted(groups.items()):
        failed=[e for e in items if e["event_type"]=="ssh_failed"]
        successes=[e for e in items if e["event_type"]=="ssh_success"]
        scenarios=[]
        if len(failed)>=3 and successes:
            scenarios.append(("AUTH-002","HIGH","Repeated SSH failures followed by success",failed+successes,"Review account activity"))
        elif len(failed)>=3:
            scenarios.append(("AUTH-001","MEDIUM","Repeated SSH failures",failed,"Review source address"))
        for e in items:
            if e["event_type"]=="malware_detected":
                scenarios.append(("ENDPOINT-001","HIGH","Simulated malware detection",[e],"Review endpoint alert"))
            if e["event_type"]=="privilege_change":
                scenarios.append(("IAM-001","MEDIUM","Privilege change requiring approval",[e],"Verify authorized change"))
        for rule,severity,reason,evidence,action in scenarios:
            alerts.append(dict(rule=rule,severity=severity,host=host,src_ip=ip,reason=reason,
                               event_ids=[e["id"] for e in evidence],recommended_action=action))
    return alerts

def main():
    root=Path(__file__).resolve().parents[1]
    events=[json.loads(line) for line in (root/"data/events.jsonl").read_text().splitlines() if line.strip()]
    alerts=analyze(events)
    (root/"reports").mkdir(exist_ok=True)
    (root/"reports/alerts.json").write_text(json.dumps(alerts,indent=2)+"\n")
    lines=["# Synthetic Alert Triage Report","",f"**Alerts:** {len(alerts)}",""]
    for a in alerts:
        lines += [f"## {a['rule']} ({a['severity']})",f"Host: {a['host']} | IP: {a['src_ip']}",
                  f"Reason: {a['reason']}",f"Evidence: {', '.join(a['event_ids'])}",
                  f"Follow-up: {a['recommended_action']}",""]
    (root/"reports/triage_summary.md").write_text("\n".join(lines))
    print(f"Generated {len(alerts)} simulated alerts")

if __name__=="__main__": main()
