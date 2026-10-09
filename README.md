# AWS IAM Static Policy Auditor

A lightweight Python CLI tool designed to analyze static AWS IAM JSON policies for security risks, over-privileged permissions, and common misconfigurations.

## Features
- Scans static AWS IAM JSON policies for wildcard permissions (`*`).
- Detects service-level and full administrative wildcards.
- Simple and efficient command-line interface built with Python.

## Installation

```bash
git clone [https://github.com/abrarkhan12618-cell/aws-iam-policy-auditor.git](https://github.com/abrarkhan12618-cell/aws-iam-policy-auditor.git)
cd aws-iam-policy-auditor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
