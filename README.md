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
git clone [https://github.com/abrarkhan12618-cell/aws-iam-policy-auditor.git](https://github.com/abrarkhan12618-cell/aws-iam-policy-auditor.git)
cd aws-iam-policy-auditor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
