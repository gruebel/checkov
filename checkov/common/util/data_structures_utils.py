from typing import Generator, Any, Union, Dict, List


def get_inner_dict(source_dict: Dict[str, Dict[str, Any]], path_as_list: List[str]) -> Dict[str, Any]:
    result = source_dict
    for index in path_as_list:
        result = result[index]
    return result


def merge_dicts(*dicts: Dict[Any, Any]) -> Dict[Any, Any]:
    """
    Merges two or more dicts. If there are duplicate keys, later dict arguments take precedence.

    Null, empty, or non-dict arguments are qiuetly skipped.
    :param dicts:
    :return:
    """
    res: Dict[Any, Any] = {}
    for d in dicts:
        if not d or type(d) != dict:
            continue
        res = {**res, **d}
    return res


def generator_reader_wrapper(g: Generator[Any, Any, Any]) -> Union[None, Any]:
    try:
        return next(g)
    except StopIteration:
        return None


def search_deep_keys(
    search_text: str, obj: Union[Dict[str, Any], List[Union[str, Dict[str, Any]]]], path: List[Union[int, str]]
) -> List[Union[int, str, List[str]]]:
    """Search deep for keys and get their values"""
    keys: List[Union[int, str, List[str]]] = []
    if isinstance(obj, dict):
        for key in obj:
            pathprop = path[:]
            pathprop.append(key)
            if key == search_text:
                pathprop.append(obj[key])
                keys.append(pathprop)
                # pop the last element off for nesting of found elements for
                # dict and list checks
                pathprop = pathprop[:-1]
            if isinstance(obj[key], dict):
                if key != "parent_metadata":
                    # Don't go back to the parent metadata, it is scanned for the parent
                    keys.extend(search_deep_keys(search_text, obj[key], pathprop))
            elif isinstance(obj[key], list):
                for index, item in enumerate(obj[key]):
                    pathproparr = pathprop[:]
                    pathproparr.append(index)
                    keys.extend(search_deep_keys(search_text, item, pathproparr))
    elif isinstance(obj, list):
        for index, item in enumerate(obj):
            pathprop = path[:]
            pathprop.append(index)
            keys.extend(search_deep_keys(search_text, item, pathprop))

    return keys


def find_in_dict(obj: Dict[str, Any], key_path: str) -> Any:
    val = obj
    key_list = key_path.split("/")
    for key in key_list:
        val = val.get(key)
        if val is None:
            return None
    return val
