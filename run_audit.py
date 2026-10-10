import json
import argparse
import sys

def parse_arguments():
    parser = argparse.ArgumentParser(description="Lightweight Python-based AWS IAM Static Policy Auditor")
    parser.add_argument("-f", "--file", required=True, help="Path to the IAM policy JSON file")
    return parser.parse_args()

def audit_policy(policy_path):
    print("[*] Auditing IAM policy:", policy_path)
    try:
        with open(policy_path, 'r') as f:
            policy = json.load(f)
    except Exception as e:
        print("[-] Error loading JSON file:", e)
        sys.exit(1)

    findings = []
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for idx, stmt in enumerate(statements):
        if stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        if "*" in actions and "*" in resources:
            findings.append({
                "id": "IAM-001",
                "severity": "CRITICAL",
                "vector": "Full Administrative Wildcard Access",
                "description": "Statement index " + str(idx) + ": Unrestricted actions (*) across all resources (*)."
            })

        service_wildcards = [act for act in actions if act.endswith(":*") and act != "*"]
        if service_wildcards:
            findings.append({
                "id": "IAM-002",
                "severity": "HIGH",
                "vector": "Service-Level Wildcard Access",
                "description": "Statement index " + str(idx) + ": Contains broad service-level wildcards: " + str(service_wildcards)
            })

    report = {
        "target_policy": policy_path,
        "total_findings": len(findings),
        "findings": findings
    }
    
    with open("audit_report.json", "w") as rf:
        json.dump(report, rf, indent=4)

    print("\n[+] Audit Complete! Found", len(findings), "issues.")
    for f in findings:
        print("  [" + f['severity'] + "] " + f['vector'] + " (" + f['id'] + ")")
        print("      -> " + f['description'])
    print("\n[+] Report saved to audit_report.json")

if __name__ == "__main__":
    args = parse_arguments()
    audit_policy(args.file)
