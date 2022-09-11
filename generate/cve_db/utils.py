from __future__ import annotations

import logging

from checkov.github.dal import Github
from generate.cve_db.github_types import (
    SecurityVulnerability,
    RepoTag,
    RepoCommitHash,
    PackageData,
    PackageVulnerability,
)


def get_package_vulnerabilities(github: Github, ecosystem: str) -> dict[str, PackageData] | None:
    """Retrieves the vulnerabilities from the GitHub Advisory DB"""

    # end cursor valuation not needed yet
    result = github._request_graphql(
        query="""
            query ($ecosystem: SecurityAdvisoryEcosystem!) {
              securityVulnerabilities(ecosystem: $ecosystem, first: 50) {
                nodes {
                  advisory {
                    description
                    cvss {
                      score
                      vectorString
                    }
                    identifiers {
                      type
                      value
                    }
                    permalink
                    publishedAt
                    summary
                  }
                  firstPatchedVersion {
                    identifier
                  }
                  package {
                    name
                  }
                  severity
                  vulnerableVersionRange
                }
              }
            }
        """,
        variables={"ecosystem": ecosystem},
    )

    if not result:
        logging.error(f"Failed to retrieve vulnerabilities for ecosystem {ecosystem}")
        return None

    package_vulnerabilities: dict[str, PackageData] = {}

    vulnerability_nodes = result["data"]["securityVulnerabilities"]["nodes"]
    for node in vulnerability_nodes:
        package_name, vulnerability = create_vulnerability_entry(node)

        if package_name in package_vulnerabilities:
            package_vulnerabilities[package_name]["vulnerabilities"].append(vulnerability)
        else:
            package_vulnerabilities[package_name] = {"vulnerabilities": [vulnerability]}

    return package_vulnerabilities


def create_vulnerability_entry(vulnerability_node: SecurityVulnerability) -> tuple[str, PackageVulnerability]:
    """Creates a vulnerability entry for the DB"""

    # advisory block
    advisory = vulnerability_node["advisory"]

    cvss = advisory["cvss"]
    cvss_score = cvss["score"]
    cvss_vector = cvss["vectorString"]

    identifiers = advisory["identifiers"]
    cve_id = "UNKNOWN"  # should be either GHSA or CVE at the end (CVE preferred)
    for identifier in identifiers:
        identifier_type = identifier["type"]
        identifier_value = identifier["value"]
        if identifier_type == "CVE":
            cve_id = identifier_value
            break
        elif identifier_type == "GHSA":
            cve_id = identifier_value

    description = advisory["description"]
    link = advisory["permalink"]
    published_date = advisory["publishedAt"]

    # firstPatchedVersion block
    patched_version = vulnerability_node["firstPatchedVersion"]
    status = "open"
    patched_version_identifier = None
    if patched_version:
        patched_version_identifier = patched_version["identifier"]
        if patched_version_identifier:
            status = f"fixed in {patched_version_identifier}"

    # package block
    package = vulnerability_node["package"]
    package_name = package["name"]

    # severity & vulnerableVersionRange block
    severity = vulnerability_node["severity"]  # TODO: change to twistcli style
    impacted_versions = vulnerability_node["vulnerableVersionRange"]

    vulnerability = {
        "id": cve_id,
        "status": status,
        "cvss": cvss_score,
        "vector": cvss_vector,
        "description": description,
        "severity": severity,
        "packageName": package_name,
        "link": link,
        "riskFactors": [],  # not available, but parts could be created out of 'cvss_vector'
        "impactedVersions": impacted_versions,
        "publishedDate": published_date,
        "discoveredDate": published_date,
        "fixDate": None,  # if available will be replaced with the commit date
        "fixedVersion": patched_version_identifier,  # used to get the 'fixDate'
        "fixedCommitHash": None,  # if available will be replaced with the commit hash of the tag
    }

    return package_name, vulnerability


def get_repo_info(
    github: Github, repo_owner: str, repo_name: str
) -> tuple[dict[str, RepoTag], dict[str, RepoCommitHash]] | None:
    """Retrieves the repository info from the GitHub Advisory DB"""

    tags: dict[str, RepoTag] = {}
    commit_hashes: dict[str, RepoCommitHash] = {}

    end_cursor = ""  # if there are more tags to fetch, then it will be overridden after each request
    for _ in range(10):  # just a safety net to not hang in an infinite loop
        result = github._request_graphql(
            query="""
                query ($repo_name: String!, $repo_owner: String!, $end_cursor: String!) {
                  repository(name: $repo_name, owner: $repo_owner) {
                    refs(refPrefix: "refs/tags/", first: 50, after: $end_cursor) {
                      edges {
                        node {
                          name
                          target {
                            oid
                            ... on Commit {
                              committedDate
                            }
                            repository {
                              licenseInfo {
                                spdxId
                              }
                            }
                          }
                        }
                      }
                      pageInfo {
                        hasNextPage
                        endCursor
                      }
                    }
                  }
                }
            """,
            variables={
                "end_cursor": end_cursor,
                "repo_name": repo_name,
                "repo_owner": repo_owner,
            },
        )

        if not result:
            logging.error(f"Failed to retrieve repo info for {repo_owner}/{repo_name}")
            return None

        repo_refs = result["data"]["repository"]["refs"]
        for repo_ref_edges in repo_refs["edges"]:
            tag_name = repo_ref_edges["node"]["name"]

            node_target = repo_ref_edges["node"]["target"]
            commit_hash = node_target["oid"]
            commit_date = node_target.get("committedDate")
            spdx_id = node_target["repository"]["licenseInfo"]["spdxId"]

            tags[tag_name] = {
                "commit_hash": commit_hash,
                "commit_date": commit_date,
                "license_spdx_id": spdx_id,
            }
            commit_hashes[commit_hash] = {
                "tag_name": tag_name,
                "commit_date": commit_date,
                "license_spdx_id": spdx_id,
            }

        has_next = repo_refs["pageInfo"]["hasNextPage"]
        if has_next:
            end_cursor = repo_refs["pageInfo"]["endCursor"]

    return tags, commit_hashes
