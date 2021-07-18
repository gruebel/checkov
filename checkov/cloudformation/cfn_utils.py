import logging
import os
from typing import Optional, List, Tuple, Dict, Any

import dpath.util

from checkov.cloudformation.checks.resource.base_registry import Registry
from checkov.cloudformation.checks.resource.registry import cfn_registry
from checkov.cloudformation.context_parser import ContextParser
from checkov.cloudformation.graph_builder.graph_components.block_types import CloudformationTemplateSections
from checkov.cloudformation.parser import parse
from checkov.cloudformation.parser.node import dict_node, list_node, str_node
from checkov.common.runners.base_runner import filter_ignored_paths

CF_POSSIBLE_ENDINGS = frozenset([".yml", ".yaml", ".json", ".template"])


def get_resource_tags(entity: Dict[str_node, dict_node], registry: Registry = cfn_registry) -> Optional[Dict[str, str]]:
    entity_details = registry.extract_entity_details(entity)

    if not entity_details:
        return None

    entity_config = entity_details[-1]

    if not isinstance(entity_config, dict):
        return None

    try:
        properties = entity_config.get("Properties")
        if properties:
            tags = properties.get("Tags")
            if tags:
                if isinstance(tags, list_node):
                    tag_dict = {tag["Key"]: get_entity_value_as_string(tag["Value"]) for tag in tags}
                    return tag_dict
                elif isinstance(tags, dict_node):
                    tag_dict = {
                        str(key): get_entity_value_as_string(value)
                        for key, value in tags.items()
                        if key not in ("__startline__", "__endline__")
                    }
                    return tag_dict
    except:
        logging.warning(f"Failed to parse tags for entity {entity}")

    return None


def get_entity_value_as_string(value: Any) -> str:
    """
    Handles different type of entities with possible CFN function substitutions. Returns the simplest possible string value
    (without performing any function calls).

    Examples:
    Key: Value  # returns simple string

    Key: !Ref ${AWS::AccountId}-data  # returns ${AWS::AccountId}-data

    Key:
    - ${account}-data
    - account: !Ref ${AWS::AccountId}

    # returns ${account}-data

    :param value:
    :return:
    """
    if isinstance(value, dict):
        (function, value) = next(iter(value.items()))
        # If the value is a long-form function, then the first element is the template string (technically str_node)
        # Otherwise the dict value is the template string
        if isinstance(value, list):
            if "Join" in function:
                # Join looks like !Join [, [V1, V2, V3]]
                join_str = str(value[0])
                return join_str.join([str(v) for v in value[1]])
            else:
                return str(value[0])
        else:
            return str(value)
    else:
        return str(value)


def get_folder_definitions(
    root_folder: str, excluded_paths: Optional[List[str]]
) -> Tuple[Dict[str, dict_node], Dict[str, List[Tuple[int, str]]]]:
    files_list = []
    for root, d_names, f_names in os.walk(root_folder):
        filter_ignored_paths(root, d_names, excluded_paths)
        filter_ignored_paths(root, f_names, excluded_paths)
        for file in f_names:
            file_ending = os.path.splitext(file)[1]
            if file_ending in CF_POSSIBLE_ENDINGS:
                files_list.append(os.path.join(root, file))

    definitions: Dict[str, dict_node] = {}
    definitions_raw: Dict[str, List[Tuple[int, str]]] = {}
    for file in files_list:
        relative_file_path = f"/{os.path.relpath(file, os.path.commonprefix((root_folder, file)))}"
        try:
            template, template_lines = parse(file)
            if isinstance(template, dict_node) and isinstance(template.get("Resources"), dict_node):
                definitions[relative_file_path] = template
                definitions_raw[relative_file_path] = template_lines
        except TypeError:
            logging.info(f"CloudFormation skipping {file} as it is not a valid CF template")

    return definitions, definitions_raw


def build_definitions_context(
    definitions: Dict[str, dict_node], definitions_raw: Dict[str, List[Tuple[int, str]]], root_folder: str
) -> Dict[str, Dict[str, Any]]:
    definitions_context: Dict[str, Dict[str, Any]] = {}
    # iterate on the files
    for file_path, file_path_definitions in definitions.items():
        # iterate on the definitions (Parameters, Resources, Outputs...)
        for file_path_definition, definition in file_path_definitions.items():
            if (
                isinstance(file_path_definition, str_node)
                and file_path_definition.upper() in CloudformationTemplateSections.__members__
                and isinstance(definition, dict_node)
            ):
                # iterate on the actual objects of each definition
                for attribute, attr_value in definition.items():
                    if isinstance(attr_value, dict_node):
                        start_line = attr_value.start_mark.line
                        end_line = attr_value.end_mark.line
                        code_lines = definitions_raw[file_path][start_line - 1 : end_line]
                        file_abs_path = create_file_abs_path(root_folder, file_path)
                        dpath.new(
                            definitions_context,
                            [file_abs_path, str(file_path_definition), str(attribute)],
                            {"start_line": start_line, "end_line": end_line, "code_lines": code_lines},
                        )
                        if file_path_definition.upper() == CloudformationTemplateSections.RESOURCES.value.upper():
                            skipped_checks = ContextParser.collect_skip_comments(code_lines)
                            dpath.new(
                                definitions_context,
                                [file_abs_path, str(file_path_definition), str(attribute), "skipped_checks"],
                                skipped_checks,
                            )
    return definitions_context


def create_file_abs_path(root_folder: str, cf_file: str) -> str:
    # There are a few cases here. If -f was used, there could be a leading / because it's an absolute path,
    # or there will be no leading slash; root_folder will always be none.
    # If -d is used, root_folder will be the value given, and -f will start with a / (hardcoded above).
    # The goal here is simply to get a valid path to the file (which cf_file does not always give).
    if cf_file.startswith("/"):
        path_to_convert = (root_folder + cf_file) if root_folder else cf_file
    else:
        path_to_convert = (os.path.join(root_folder, cf_file)) if root_folder else cf_file

    return os.path.abspath(path_to_convert)
