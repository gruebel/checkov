from __future__ import annotations

import logging
import os
import tempfile
from abc import abstractmethod
from collections.abc import Iterable
from pathlib import Path
from typing import Any, TYPE_CHECKING, Generic, TypeVar

from checkov.common.bridgecrew.check_type import CheckType
from checkov.common.models.enums import ErrorStatus
from checkov.common.output.common import UNKNOWN_LICENSE
from checkov.common.output.report import Report
from checkov.common.sca.commons import should_run_scan
from checkov.common.sca.github_advisory_db import GitHubAdvisoryDatabase
from checkov.common.sca.output import add_to_report_sca_data
from checkov.common.typing import _LicenseStatus
from checkov.sca_package_2.runner import Runner as ScaPackageRunner

if TYPE_CHECKING:
    from checkov.common.bridgecrew.platform_integration import BcPlatformIntegration
    from checkov.runner_filter import RunnerFilter
    from networkx import DiGraph

_Definitions = TypeVar("_Definitions")


def enable_package_referencer(
    bc_integration: BcPlatformIntegration, frameworks: Iterable[str] | None, skip_frameworks: Iterable[str] | None
) -> bool:
    """Checks, if Package Referencer should be enabled"""

    if skip_frameworks and CheckType.SCA_PACKAGE in skip_frameworks:
        return False

    if bc_integration.bc_api_key:
        if not frameworks:
            return True
        if any(framework in frameworks for framework in ("all", CheckType.SCA_PACKAGE)):
            return True

    return False


class Package:
    __slots__ = (
        "commit_hash",
        "end_line",
        "file_path",
        "licenses",
        "name",
        "package_file_path",
        "reference_name",
        "related_resource_id",
        "start_line",
        "version",
    )

    def __init__(
        self,
        reference_name: str,
        name: str,
        version: str,
        file_path: str,
        start_line: int,
        end_line: int,
        related_resource_id: str | None = None,
        package_file_path: Path | None = None,
    ) -> None:
        """
        ex.
        reference_name: 'hashicorp/vault-action@v2.1.0'
        name: 'hashicorp/vault-action'
        version: 'v2.1.0'
        file_path: '.github/workflows/vulnerable_action.yaml'
        start_line: 8
        end_line: 17
        related_resource_id: xyz
        """
        self.reference_name = reference_name
        self.name = name
        self.file_path = file_path
        self.end_line = end_line
        self.start_line = start_line
        self.related_resource_id = related_resource_id
        self.package_file_path = package_file_path
        self.licenses = UNKNOWN_LICENSE  # will be replaced later, if possible

        # version can be semver style or a commit hash
        self.commit_hash: str | None = None
        self.version: str | None = None
        if len(version) == 40:
            self.commit_hash = version
        else:
            self.version = version

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__

        return False

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash((self.reference_name, self.file_path, self.start_line, self.end_line))


class PackageReferencerMixin(Generic[_Definitions]):
    """Mixin class to simplify package reference search"""

    def check_package_references(
        self,
        root_path: str | Path | None,
        runner_filter: RunnerFilter,
        graph_connector: DiGraph | None = None,
        definitions: _Definitions | None = None,
        definitions_raw: dict[str, list[tuple[int, str]]] | None = None,
    ) -> Report | None:
        """Tries to find package references in IaC templates"""
        from checkov.common.bridgecrew.platform_integration import bc_integration

        # skip complete run, if flag '--check' was used without a CVE check ID
        if not should_run_scan(runner_filter.checks):
            return None

        report = None

        with tempfile.TemporaryDirectory() as temp_dir_name:
            package_files = self.extract_package_files(
                graph_connector=graph_connector,
                definitions=definitions,
                definitions_raw=definitions_raw,
                download_path=Path(temp_dir_name),
            )
            if package_files:
                report = self.process_package_files(package_files=package_files, runner_filter=runner_filter)

        packages = self.extract_packages(
            graph_connector=graph_connector,
            definitions=definitions,
            definitions_raw=definitions_raw,
        )
        if not packages:
            return report

        logging.info(f"Found {len(packages)} package references {[package.name for package in packages]}")

        database = GitHubAdvisoryDatabase()

        if not report:
            report = Report(CheckType.SCA_PACKAGE)
        root_path = Path(root_path) if root_path else None
        check_class = f"{database.__module__}.{database.__class__.__qualname__}"
        report_type = CheckType.SCA_PACKAGE

        for package in packages:
            self.add_package_records(
                database=database,
                report=report,
                root_path=root_path,
                check_class=check_class,
                package=package,
                runner_filter=runner_filter,
                report_type=report_type,
                bc_integration=bc_integration,
            )

        return report

    def add_package_records(
        self,
        database: GitHubAdvisoryDatabase,
        report: Report,
        root_path: Path | None,
        check_class: str,
        package: Package,
        runner_filter: RunnerFilter,
        report_type: str,
        bc_integration: BcPlatformIntegration,
    ) -> None:
        """Adds an package record to the given report, if possible"""

        result = database.check(package_name=package.name, version=package.version, commit_hash=package.commit_hash)
        if result:
            if package.version:
                package_tag = database.get_tag_entry(package_name=package.name, tag_name=package.version)
                if package_tag:
                    package.commit_hash = package_tag["commit_hash"]
                    package.licenses = package_tag["license_spdx_id"]

            package_file_path = package.file_path
            if root_path:
                try:
                    package_file_path = str(Path(package_file_path).relative_to(root_path))
                except ValueError:
                    # Path.is_relative_to() was implemented in Python 3.9
                    pass
            rootless_file_path = package_file_path.replace(Path(package_file_path).anchor, "", 1)
            short_commit_hash = f"commit:{package.commit_hash[:10]}" if package.commit_hash else "commit:unknown"
            rootless_file_path_to_report = (
                f"{rootless_file_path} ({package.reference_name} lines:{package.start_line}-"
                f"{package.end_line} ({short_commit_hash}))"
            )

            add_to_report_sca_data(
                report=report,
                check_class=check_class,
                scanned_file_path=os.path.abspath(package_file_path),
                rootless_file_path=rootless_file_path_to_report,
                runner_filter=runner_filter,
                vulnerabilities=result,
                packages=[],  # no need to fill, because all added packages have a vulnerability
                license_statuses=[],  # if we have a license, then we should check, if it is acceptable
                report_type=report_type,
            )

    def enrich_package_info(self, database: GitHubAdvisoryDatabase, package: Package) -> None:
        """Adds missing data to a package instance"""

        if package.version:
            tag = database.get_tag_entry(package_name=package.name, tag_name=package.version)
            if tag:
                package.commit_hash = tag["commit_hash"]
                package.licenses = tag["license_spdx_id"]
        elif package.commit_hash:
            commit_hash = database.get_commit_hash_entry(package_name=package.name, commit_hash=package.commit_hash)
            if commit_hash:
                package.version = commit_hash["tag_name"]
                package.licenses = commit_hash["license_spdx_id"]

    @abstractmethod
    def extract_packages(
        self,
        graph_connector: DiGraph | None = None,
        definitions: _Definitions | None = None,
        definitions_raw: dict[str, list[tuple[int, str]]] | None = None,
    ) -> list[Package]:
        """Tries to find package references in the graph or supported resource"""

        pass

    def process_package_files(self, package_files: list[Package], runner_filter: RunnerFilter) -> Report:
        runner = ScaPackageRunner()
        report = Report(runner.check_type)

        files = [
            package_file.package_file_path
            for package_file in package_files
            if package_file.package_file_path is not None
        ]

        logging.info(f"Found {len(files)} package file references {[package_file.reference_name for package_file in package_files]}")

        scan_results = runner.prepare_and_scan(root_folder=None, files=files, runner_filter=runner_filter)
        if scan_results is None:
            report.set_error_status(ErrorStatus.ERROR)
            return report

        for path, result in scan_results.items():
            if not result:
                continue
            package_file_path = Path(path)

            vulnerabilities = result.get("vulnerabilities") or []
            packages = result.get("packages") or []

            license_statuses = [
                _LicenseStatus(
                    package_name=elm["packageName"],
                    package_version=elm["packageVersion"],
                    policy=elm["policy"],
                    license=elm["license"],
                    status=elm["status"],
                )
                for elm in result.get("license_statuses") or []
            ]

            # rootless_file_path = str(package_file_path).replace(package_file_path.anchor, "", 1)
            file_name = package_file_path.name
            scanned_package_file = next((package_file for package_file in package_files if str(package_file.package_file_path).endswith(path)), None)
            if not scanned_package_file:
                # this shouldn't happen
                continue

            short_commit_hash = f"commit:{scanned_package_file.commit_hash[:10]}" if scanned_package_file.commit_hash else "commit:unknown"
            rootless_file_path_to_report = (
                f"{file_name} ({scanned_package_file.reference_name} lines:{scanned_package_file.start_line}-"
                f"{scanned_package_file.end_line} ({short_commit_hash}))"
            )

            add_to_report_sca_data(
                report=report,
                check_class=runner._check_class,
                scanned_file_path=os.path.abspath(scanned_package_file.file_path),
                rootless_file_path=rootless_file_path_to_report,
                runner_filter=runner_filter,
                vulnerabilities=vulnerabilities,
                packages=packages,
                license_statuses=license_statuses,
                report_type=runner.report_type,
                dependencies=result.get("dependencies", None),
            )

        return report

    @abstractmethod
    def extract_package_files(
        self,
        graph_connector: DiGraph | None = None,
        definitions: _Definitions | None = None,
        definitions_raw: dict[str, list[tuple[int, str]]] | None = None,
        download_path: Path | None = None,
    ) -> list[Package]:
        """Tries to find package file references in the graph or supported resource"""

        pass
