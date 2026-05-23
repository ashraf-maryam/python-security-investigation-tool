log_file = "logs/sample_auth.log"

with open(log_file, "r") as file:
    logs = file.readlines()

failed_logins = 0
failed_ips = {}

print("=== Suspicious Login Activity ===")

for line in logs:
    if "Failed password" in line:
        failed_logins += 1
        print(line.strip())

        parts = line.split()
        ip_address = parts[10]

        if ip_address in failed_ips:
            failed_ips[ip_address] += 1
        else:
            failed_ips[ip_address] = 1

print("\n=== Failed Login Attempts by IP ===")

for ip, count in failed_ips.items():

    if count >= 3:
        severity = "HIGH"
    elif count == 2:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    print(ip, ":", count, "attempts | Severity:", severity)

print("\n=== Investigation Summary ===")

if failed_logins >= 4:
    overall_severity = "HIGH"
elif failed_logins >= 2:
    overall_severity = "MEDIUM"
else:
    overall_severity = "LOW"

print("Overall Incident Severity:", overall_severity)

print("\nRecommendations:")

if overall_severity == "HIGH":
    print("- Investigate repeated failed login attempts")
    print("- Review SSH authentication settings")
    print("- Consider blocking suspicious IP addresses")

elif overall_severity == "MEDIUM":
    print("- Monitor suspicious authentication activity")
    print("- Review affected user accounts")

else:
    print("- Continue monitoring logs")

report = f"""
=== Security Investigation Report ===

Overall Severity: {overall_severity}

Total Failed Login Attempts: {failed_logins}

Suspicious IP Activity:
"""

for ip, count in failed_ips.items():
    report += f"- {ip}: {count} failed attempts\n"

report += """
Recommendations:
- Investigate suspicious login activity
- Review SSH authentication controls
- Consider blocking repeated attacker IPs
"""

with open("reports/security_report.txt", "w") as file:
    file.write(report)

print("\nSecurity report saved to reports/security_report.txt")