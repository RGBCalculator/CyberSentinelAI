import json
import os
import sys

# Ensure backend root is in PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from datetime import datetime
from app.schemas.posture import (
    SecurityPosture, Repository, CodeFinding, CodeLocation,
    BlastRadius, DependencyPath, InvestigationTask, Severity
)

def generate_demo_fixture():
    print("Generating SecurityPosture Demo Fixture...")

    # 1. Base Repository Info
    repo = Repository(
        name="internal-finance-api",
        url="https://github.com/cybersentinel-demo/internal-finance-api",
        commit_hash="a1b2c3d4e5f67890",
        branch="main"
    )

    # 2. Critical Finding: SQL Injection
    sqli_finding = CodeFinding(
        rule_id="semgrep-python-sqli",
        title="Raw SQL Execution (SQLi)",
        description="User input is concatenated directly into a raw SQL query, allowing for SQL Injection.",
        severity=Severity.CRITICAL,
        risk_score=95,
        location=CodeLocation(
            file_path="src/database/transactions.py",
            start_line=42,
            end_line=44,
            snippet='query = f"SELECT * FROM transactions WHERE user_id = \'{user_id}\'"\ncursor.execute(query)'
        ),
        blast_radius=BlastRadius(
            affected_files=["src/api/routes.py", "src/services/billing.py"],
            affected_endpoints=["GET /api/v1/transactions", "POST /api/v1/billing/process"],
            dependency_paths=[
                DependencyPath(source="get_user_transactions", target="api_get_transactions", relationship="imported_by")
            ]
        ),
        investigation_plan=[
            InvestigationTask(
                title="Verify user input sanitization",
                description="Check if `user_id` in `api/routes.py` is cast to an Integer or sanitized before reaching the DB layer."
            ),
            InvestigationTask(
                title="Check WAF logs",
                description="Query recent access logs for `/api/v1/transactions` to see if SQLi payloads have been attempted."
            )
        ]
    )

    # 3. High Finding: Hardcoded Secret
    secret_finding = CodeFinding(
        rule_id="trufflehog-aws-key",
        title="Hardcoded AWS Access Key",
        description="An AWS access key is hardcoded in a configuration file.",
        severity=Severity.HIGH,
        risk_score=85,
        location=CodeLocation(
            file_path="src/config/settings.py",
            start_line=12,
            end_line=12,
            snippet='AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
        ),
        blast_radius=BlastRadius(
            affected_files=["src/services/s3_upload.py"],
            affected_endpoints=["POST /api/v1/documents/upload"],
            dependency_paths=[
                DependencyPath(source="settings", target="s3_upload", relationship="imported_by")
            ]
        ),
        investigation_plan=[
            InvestigationTask(
                title="Verify key status",
                description="Check AWS IAM to see if `AKIAIOSFODNN7EXAMPLE` is active."
            ),
            InvestigationTask(
                title="Check CloudTrail",
                description="Review CloudTrail logs for unauthorized API calls using this key."
            )
        ]
    )

    # 4. Construct SecurityPosture
    posture = SecurityPosture(
        repository=repo,
        total_findings=2,
        critical_findings=1,
        high_findings=1,
        overall_risk_score=95,
        findings=[sqli_finding, secret_finding]
    )

    # Ensure output directory exists
    output_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(output_dir, exist_ok=True)

    output_path = os.path.join(output_dir, "demo_posture.json")

    with open(output_path, "w") as f:
        f.write(posture.model_dump_json(indent=2))

    print(f"Fixture successfully generated at: {output_path}")

if __name__ == "__main__":
    # Ensure backend root is in PYTHONPATH
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    generate_demo_fixture()
