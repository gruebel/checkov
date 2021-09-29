import json
from collections import defaultdict
from copy import deepcopy
from pathlib import Path
from typing import Dict, List

from typing_extensions import TypedDict

from checkov.common.output.report import Report
from checkov.common.output.record import Record


class _Finding(TypedDict):
    check_ids: List[str]
    resource: str


class _FailedCheck(TypedDict):
    file: str
    findings: List[_Finding]


class _FailedChecks(TypedDict):
    failed_checks: List[_FailedCheck]


class Baseline:
    failed_checks: List[_FailedCheck]
    findings: Dict[str, List[_Finding]] = defaultdict(list)
    path = ""

    def add_findings_from_report(self, report: Report) -> None:
        for check in report.failed_checks:
            try:
                existing = next(x for x in self.findings[check.file_path] if x["resource"] == check.resource)
            except StopIteration:
                existing = {"resource": check.resource, "check_ids": []}
                self.findings[check.file_path].append(existing)
            existing["check_ids"].append(check.check_id)
            existing["check_ids"].sort()  # Sort the check IDs to be nicer to the eye

    def to_dict(self) -> _FailedChecks:
        """
        The output of this class needs to be very explicit, hence the following structure of the dict:
        {
            "failed_checks": [
                {
                    "file": "path/to/file",
                    "findings: [
                        {
                            "resource": "aws_s3_bucket.this",
                            "check_ids": [
                                "CKV_AWS_1",
                                "CKV_AWS_2",
                                "CKV_AWS_3"
                            ]
                        }
                    ]
                }
            ]
        }
        """
        failed_checks_list: List[_FailedCheck] = [
            {"file": file, "findings": deepcopy(findings)} for file, findings in self.findings.items()
        ]

        resp: _FailedChecks = {"failed_checks": failed_checks_list}
        return resp

    def compare_and_reduce_reports(self, scan_reports: List[Report]) -> None:
        for scan_report in scan_reports:
            scan_report.passed_checks = [
                check for check in scan_report.passed_checks if self._is_check_in_baseline(check)
            ]
            scan_report.skipped_checks = [
                check for check in scan_report.skipped_checks if self._is_check_in_baseline(check)
            ]
            scan_report.failed_checks = [
                check for check in scan_report.failed_checks if not self._is_check_in_baseline(check)
            ]

    def _is_check_in_baseline(self, check: Record) -> bool:
        failed_check_id = check.check_id
        failed_check_resource = check.resource
        for baseline_failed_check in self.failed_checks:
            for finding in baseline_failed_check["findings"]:
                if finding["resource"] == failed_check_resource and failed_check_id in finding["check_ids"]:
                    return True
        return False

    def from_json(self, file_path: str) -> None:
        self.path = file_path
        baseline_raw = json.loads(Path(file_path).read_text())
        self.failed_checks = baseline_raw.get("failed_checks", [])
