import os
from pathlib import Path
from typing import List, Union, Set




def config_file_paths(dir_path: Union[str, "os.PathLike[str]"]) -> Set[str]:
    return {os.path.join(dir_path, ".checkov.yaml"), os.path.join(dir_path, ".checkov.yml")}


def get_default_config_paths(argv: List[str]) -> List[str]:
    """
    Checkov looks for .checkov.yml or .checkov.yaml file in the directory (--directory) against which it is run.
    If that does not have the config file, the current working directory is checked followed by checking the user's
    home directory is searched.
    :param argv: List of CLI args from sys.argv.
    :return: List of default config file paths.
    """
    dir_paths = set()
    dir_paths.update(config_file_paths(Path.home()))
    dir_paths.update(config_file_paths(Path.cwd()))
    for i, v in enumerate(argv):
        if v in ["-d", "--directory"]:
            dir_paths.update(config_file_paths(argv[i + 1]))
    return list(dir_paths)


def should_scan_hcl_files():
    from checkov.common.models.consts import SCAN_HCL_FLAG  # prevent circular import
    return os.getenv(SCAN_HCL_FLAG, default="false").lower() == "true"
