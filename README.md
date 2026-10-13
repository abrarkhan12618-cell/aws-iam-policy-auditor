# AWS IAM Static Policy Auditor

A lightweight Python CLI tool that statically analyzes AWS IAM JSON policies for wildcard permissions.

> **Note:** This is a learning project. It is not a replacement for mature tools such as Prowler or Cloudsplaining.

## Features

- Scans static AWS IAM JSON policies for wildcard permissions.
- Detects full administrative wildcards (`IAM-001`) and service-level wildcards such as `s3:*` (`IAM-002`).
- Handles string and list values for `Action` and `Resource`, and skips `Deny` statements.
- Prints findings to the terminal and exports them as a structured JSON report.

## Installation

```bash
git clone https://github.com/abrarkhan12618-cell/aws-iam-policy-auditor.git
cd aws-iam-policy-auditor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

## Usage

```bash
python3 run_audit.py -f path/to/policy.json
```

## Example Output

```text
$ python3 run_audit.py -f test_policy.json
[*] Auditing IAM policy: test_policy.json

[+] Audit Complete! Found 1 issues.
  [CRITICAL] Full Administrative Wildcard Access (IAM-001)
      -> Statement index 0: Unrestricted actions (*) across all resources (*).

[+] Report saved to audit_report.json
```

## Limitations

This tool does **not** currently analyze:

- `NotAction` and `Condition` blocks
- Service Control Policies (SCPs) and permission boundaries
- Trust policies and resource-based policies
- Live AWS accounts (static files only, no AWS API calls)

## License

MIT. See the [LICENSE](LICENSE) file.
