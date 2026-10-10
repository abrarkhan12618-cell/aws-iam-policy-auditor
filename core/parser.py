import json
import yaml

class IAMPolicyParser:
    def __init__(self, policy_path):
        self.policy_path = policy_path

    def load_policy(self):
        with open(self.policy_path, 'r') as f:
            if self.policy_path.endswith('.yaml') or self.policy_path.endswith('.yml'):
                return yaml.safe_load(f)
            return json.load(f)

    def analyze_permissions(self):
        policy = self.load_policy()
        findings = []
        statements = policy.get("Statement", [])
        
        for stmt in statements:
            if stmt.get("Effect") == "Allow":
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                
                if "*" in actions or "admin:*" in str(actions):
                    findings.append({
                        "risk": "CRITICAL",
                        "description": "Wildcard permissions detected. Full administrative access allowed."
                    })
        return findings
