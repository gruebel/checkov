from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from checkov.github_actions.package_referencer.package_file_provider import GithubActionsPackageFileProvider
from checkov.github_actions.package_referencer.provider import GithubActionProvider

if TYPE_CHECKING:
    from checkov.common.sca.package_referencer import Package
    from networkx import DiGraph


class GithubActionsPackageReferencerManager:
    __slots__ = ("graph_connector", "download_path")

    def __init__(self, graph_connector: DiGraph, download_path: Path | None = None) -> None:
        self.graph_connector = graph_connector
        self.download_path = download_path

    def extract_packages_from_workflow(self) -> list[Package]:
        provider = GithubActionProvider(graph_connector=self.graph_connector)
        packages = provider.extract_packages_from_workflow()

        return packages

    def extract_package_files_from_workflow(self) -> list[Package]:
        if not self.download_path:
            logging.error("The 'download_path' was not set")
            return []

        provider = GithubActionsPackageFileProvider(graph_connector=self.graph_connector, download_path=self.download_path)
        packages = provider.extract_package_files_from_workflow()

        return packages
