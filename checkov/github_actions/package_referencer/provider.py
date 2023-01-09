from __future__ import annotations

import os
from typing import Any, TYPE_CHECKING, Callable

from checkov.common.graph.graph_builder import CustomAttributes
from checkov.common.sca.package_referencer import Package
from checkov.common.util.consts import START_LINE, END_LINE
from checkov.common.util.str_utils import removeprefix
from checkov.github_actions.graph_builder.graph_components.resource_types import ResourceType

if TYPE_CHECKING:
    from networkx import DiGraph
    from typing_extensions import TypeAlias

_ExtractPackagesCallableAlias: TypeAlias = Callable[["dict[str, Any]"], "list[dict[str, str]]"]


class GithubActionProvider:
    __slots__ = ("graph_connector", "supported_resource_types")

    def __init__(self, graph_connector: DiGraph) -> None:
        self.graph_connector = graph_connector
        self.supported_resource_types = SUPPORTED_GHA_PACKAGE_RESOURCE_TYPES

    def extract_packages_from_workflow(self) -> list[Package]:
        packages = []

        resource_nodes = [
            node
            for node, resource_type in self.graph_connector.nodes(data=CustomAttributes.RESOURCE_TYPE)
            if resource_type and resource_type in self.supported_resource_types
        ]

        supported_resources_graph = self.graph_connector.subgraph(resource_nodes)

        for _, resource in supported_resources_graph.nodes(data=True):
            resource_type = resource[CustomAttributes.RESOURCE_TYPE]

            extract_images_func = self.supported_resource_types.get(resource_type)
            if extract_images_func:
                for package_info in extract_images_func(resource):
                    packages.append(
                        Package(
                            reference_name=package_info["ref_name"],
                            name=package_info["name"],
                            version=package_info["version"],
                            file_path=resource[CustomAttributes.FILE_PATH],
                            start_line=resource[START_LINE],
                            end_line=resource[END_LINE],
                            related_resource_id=f'{removeprefix(resource[CustomAttributes.FILE_PATH], os.getenv("BC_ROOT_DIR", ""))}:{resource[CustomAttributes.ID]}',
                        )
                    )

        return packages


def extract_github_actions_from_steps(resource: dict[str, Any]) -> list[dict[str, str]]:
    packages_info: list[dict[str, str]] = []

    ref_name = resource.get("uses")
    if ref_name:
        name, version = ref_name.split("@")
        packages_info.append(
            {
                "name": name,
                "version": version,
                "ref_name": ref_name,
            }
        )

    return packages_info


# needs to be at the bottom to add the defined functions
SUPPORTED_GHA_PACKAGE_RESOURCE_TYPES: "dict[ResourceType, _ExtractPackagesCallableAlias]" = {
    ResourceType.STEPS: extract_github_actions_from_steps,
}
