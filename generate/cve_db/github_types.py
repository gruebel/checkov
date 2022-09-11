from __future__ import annotations

from typing import Any

from typing_extensions import TypedDict


class SecurityVulnerability(TypedDict):
    advisory: SecurityAdvisory
    firstPatchedVersion: SecurityAdvisoryPackageVersion | None
    package: dict[str, str]
    severity: str  # CRITICAL, HIGH, MODERATE or LOW
    vulnerableVersionRange: str


class SecurityAdvisory(TypedDict):
    cvss: CVSS
    description: str
    identifiers: list[SecurityAdvisoryIdentifier]
    permalink: str | None
    publishedAt: str  # ex. "2022-05-24T19:01:50Z"
    summary: str


class CVSS(TypedDict):
    score: float
    vectorString: str | None


class SecurityAdvisoryIdentifier(TypedDict):
    type: str  # should be usually GHSA or CVE
    value: str


class SecurityAdvisoryPackageVersion(TypedDict):
    identifier: str


class SecurityAdvisoryPackage(TypedDict):
    name: str


class PackageData(TypedDict):
    commit_hashes: dict[str, RepoCommitHash]
    tags: dict[str, RepoTag]
    vulnerabilities: list[PackageVulnerability]


class RepoCommitHash(TypedDict):
    commit_date: str | None
    license_spdx_id: str
    tag_name: str


class RepoTag(TypedDict):
    commit_date: str | None
    commit_hash: str
    license_spdx_id: str


class PackageVulnerability(TypedDict):
    id: str
    status: str
    cvss: float
    vector: str | None
    description: str
    severity: str
    packageName: str
    packageVersion: str
    link: str | None
    riskFactors: list[str]
    impactedVersions: str
    publishedDate: str
    discoveredDate: str
    fixDate: str | None
    fixedVersion: str | None
    fixedCommitHash: str | None
