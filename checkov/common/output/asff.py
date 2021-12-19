import json
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, Any, List

import boto3

from checkov.common.output.record import Record
from checkov.common.util.json_utils import CustomJSONEncoder

if TYPE_CHECKING:
    from checkov.common.output.report import Report

MAX_BATCH_SIZE = 100


class ASFF:
    # https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-syntax.html
    def __init__(self, account_id: str, region: str) -> None:
        self.account_id = str(account_id)
        self.region = region

        session = boto3.session.Session(region_name="us-west-2", profile_name="dev2")
        self.sc_client = session.client("securityhub")
        self.findings: List[Dict[str, Any]] = []

    def create_finding(self, record: Record, status: str) -> Dict[str, Any]:
        timestamp = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
        finding = {
            "SchemaVersion": "2018-10-08",
            "AwsAccountId": self.account_id,
            "ProductArn": f"arn:aws:securityhub:{self.region}:{self.account_id}:product/{self.account_id}/default",
            "Id": f"checkov-{self.region}-{self.account_id}-{record.check_id}-{record.file_path}-{record.resource}",
            "GeneratorId": f"checkov-{record.check_id}",
            "Title": record.check_name,
            "Description": record.guideline,
            "Types": [f"Software and Configuration Checks/{category.name}" for category in record.check_categories],
            "CreatedAt": timestamp,
            "UpdatedAt": timestamp,
            "Severity": {
                "Label": "MEDIUM",
            },
            "Remediation": {
                "Recommendation": {
                    "Text": "Code fix",
                    "Url": record.guideline,
                },
            },
            "Resources": [
                {
                    "Id": f"{record.file_path}:{record.resource}",  # max length 512
                    "Partition": "aws",
                    "Type": "Other",
                    "Details": {
                        "Other": {
                            "CheckID": record.check_id,
                            "CodeBlock": "".join(line for _, line in record.code_block),
                        },
                    },
                },
            ],
            "ProductFields": {
                "checkov/checkov/check_id": record.check_id,
            },
            "Compliance": {
                "Status": status,
            },
        }

        return finding

    def create_report(self, report: "Report") -> List[Dict[str, Any]]:
        for check in report.failed_checks:
            self.findings.append(self.create_finding(record=check, status="FAILED"))
        for check in report.passed_checks:
            self.findings.append(self.create_finding(record=check, status="PASSED"))

        return self.findings

    def import_findings(self) -> None:
        if len(self.findings) < MAX_BATCH_SIZE:
            chunks = [self.findings]
        else:
            chunks = [self.findings[i::MAX_BATCH_SIZE] for i in range(MAX_BATCH_SIZE)]

        for chunk in chunks:
            response = self.sc_client.batch_import_findings(Findings=chunk)
            print(json.dumps(response, indent=4, cls=CustomJSONEncoder))
