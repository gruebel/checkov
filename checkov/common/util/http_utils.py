from typing import Dict

import requests
import logging

from checkov.common.bridgecrew.bc_source import SourceType
from checkov.common.util.consts import DEV_API_GET_HEADERS, DEV_API_POST_HEADERS
from checkov.common.util.data_structures_utils import merge_dicts
from checkov.version import version as checkov_version


def extract_error_message(response: requests.Response) -> str:
    if response.content:
        try:
            content = response.json()
            if "message" in content:
                return content["message"]
        except Exception:
            logging.debug(f"Failed to parse the response content: {response.text}")

    return response.reason


def get_auth_header(token: str) -> Dict[str, str]:
    return {"Authorization": token}


def get_version_headers(client: str, client_version: str) -> Dict[str, str]:
    return {"x-api-client": client, "x-api-version": client_version, "x-api-checkov-version": checkov_version}


def get_default_get_headers(client: SourceType, client_version: str) -> Dict[str, str]:
    return merge_dicts(DEV_API_GET_HEADERS, get_version_headers(client.name, client_version))


def get_default_post_headers(client: SourceType, client_version: str) -> Dict[str, str]:
    return merge_dicts(DEV_API_POST_HEADERS, get_version_headers(client.name, client_version))
