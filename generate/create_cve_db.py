from __future__ import annotations

import json
import logging
import os

from checkov.github.dal import Github
from generate.cve_db.utils import get_repo_info, get_package_vulnerabilities

logging.getLogger().setLevel(os.getenv("LOG_LEVEL", "INFO").upper())

EXCLUDED_GHA_PACKAGES = {
    "actions/runner",  # this not a GHA, it is the actual runner itself
}


def main() -> None:
    github = Github()
    ecosystem = "ACTIONS"

    package_vulnerabilities = get_package_vulnerabilities(
        github=github,
        ecosystem=ecosystem,
        excluded_packages=EXCLUDED_GHA_PACKAGES,
    )
    if not package_vulnerabilities:
        # error message is already logged inside the method
        return

    for package_name, package_data in package_vulnerabilities.items():
        repo_owner, repo_name = package_name.split("/")

        repo_info = get_repo_info(github=github, repo_owner=repo_owner, repo_name=repo_name)
        if not repo_info:
            # error message is already logged inside the method
            return

        tags, commit_hashes = repo_info

        package_data["commit_hashes"] = commit_hashes
        package_data["tags"] = tags

        for vulnerability in package_data["vulnerabilities"]:
            fixed_version = vulnerability["fixedVersion"]

            if fixed_version:
                tag = tags.get(f"v{fixed_version}", tags.get(fixed_version))  # usually the tags are prefixed with a 'v'
                if tag:
                    vulnerability["fixDate"] = tag["commit_date"]
                    vulnerability["fixedCommitHash"] = tag["commit_hash"]

    print(json.dumps(package_vulnerabilities, indent=4))


if __name__ == "__main__":
    main()
