from __future__ import annotations
import json
import logging
import sys
from typing import TYPE_CHECKING

from packaging import version as packaging_version

if sys.version_info >= (3, 9):  # pragma: no cover
    from importlib.resources import files
else:
    from importlib_resources import files

if TYPE_CHECKING:
    from generate.cve_db.github_types import PackageData, PackageVulnerability, RepoTag, RepoCommitHash

GITHUB_ADVISORY_DB = files(__package__) / "github_advisory_db.json"


class GitHubAdvisoryDatabase:
    def __init__(self) -> None:
        self.db: dict[str, PackageData] = json.loads(GITHUB_ADVISORY_DB.read_text())

    def check(self, package_name: str, version: str | None, commit_hash: str | None) -> list[PackageVulnerability]:
        found_vulnerabilities: list[PackageVulnerability] = []

        package_data = self.db.get(package_name)
        if package_data:
            if version:
                #  referenced by tag
                tag = package_data["tags"].get(version)
                if tag:
                    tag_name = version
                else:
                    # probably referenced by branch, skip
                    return found_vulnerabilities
            elif commit_hash:
                #  referenced by commit hash
                package_commit_hash = package_data["commit_hashes"].get(commit_hash)
                if package_commit_hash:
                    tag_name = package_commit_hash["tag_name"]
                else:
                    logging.info(f"Commit {commit_hash} of package {package_name} has no tag reference")
                    return found_vulnerabilities
            else:
                logging.error(f"Package {package_name} has no version or commit hash")
                return found_vulnerabilities

            # parse the versions and compare them
            current_version = packaging_version.parse(tag_name)

            for vulnerability in package_data["vulnerabilities"]:
                # at this point either 'version' or 'commit_hash' is not None
                vulnerability["packageVersion"] = version if version else commit_hash  # type:ignore[typeddict-item]

                if not vulnerability["fixedVersion"]:
                    #  no fix available yet
                    found_vulnerabilities.append(vulnerability)
                    continue

                fixed_version = packaging_version.parse(vulnerability["fixedVersion"])
                if current_version < fixed_version:
                    # version too old
                    if commit_hash and vulnerability["fixedCommitHash"]:
                        # override tag name with commit hash, if used
                        vulnerability["status"] = vulnerability["status"].replace(
                            vulnerability["fixedVersion"], vulnerability["fixedCommitHash"]
                        )

                    found_vulnerabilities.append(vulnerability)

        return found_vulnerabilities

    def get_commit_hash_entry(self, package_name: str, commit_hash: str) -> RepoCommitHash | None:
        package_data = self.db.get(package_name)
        if package_data:
            return package_data["commit_hashes"].get(commit_hash)

        return None

    def get_tag_entry(self, package_name: str, tag_name: str) -> RepoTag | None:
        package_data = self.db.get(package_name)
        if package_data:
            return package_data["tags"].get(tag_name)

        return None
