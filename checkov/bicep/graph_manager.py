from __future__ import annotations

from pathlib import Path
from typing import Type, TYPE_CHECKING, Any

from pycep.typing import BicepJson

from checkov.bicep.parser import Parser
from checkov.bicep.utils import get_scannable_file_paths
from checkov.common.graph.db_connectors.db_connector import DBConnector
from checkov.common.graph.graph_manager import GraphManager
from checkov.bicep.graph_builder.local_graph import BicepLocalGraph

if TYPE_CHECKING:
    from checkov.common.graph.graph_builder.local_graph import LocalGraph
    from checkov.bicep.graph_builder.graph_components.blocks import BicepBlock


class BicepGraphManager(GraphManager):
    def __init__(self, db_connector: DBConnector, source: str = "Bicep") -> None:
        super().__init__(db_connector=db_connector, parser=None, source=source)

    def build_graph_from_source_directory(
        self,
        source_dir: str,
        render_variables: bool = True,
        local_graph_class: Type[LocalGraph] = BicepLocalGraph,
        parsing_errors: dict[str, Exception] | None = None,
        download_external_modules: bool = False,
        excluded_paths: list[str] | None = None,
    ) -> tuple[LocalGraph, dict[Path, BicepJson]]:
        file_paths = get_scannable_file_paths(root_folder=source_dir)
        definitions, definitions_raw, parsing_errors = Parser().get_files_definitions(file_paths)  # type:ignore[assignment]
        local_graph = self.build_graph_from_definitions(definitions)

        return local_graph, definitions

    def build_graph_from_definitions(
        self, definitions: dict[Path, BicepJson], file_path_sha_map: dict[Path, str], cached_graph: BicepLocalGraph | None = None, render_variables: bool = True
    ) -> tuple[BicepLocalGraph, list[BicepBlock]]:
        if cached_graph:
            cached_graph.definitions.update(definitions)
            cached_graph.file_path_sha_map = file_path_sha_map
            new_vertices = cached_graph.update_graph(definitions, render_variables)
            return cached_graph, new_vertices

        local_graph = BicepLocalGraph(definitions, file_path_sha_map)
        local_graph.build_graph(render_variables)
        return local_graph, local_graph.vertices
