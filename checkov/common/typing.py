from typing_extensions import TypedDict


class _SkippedCheck(TypedDict, total=False):
    id: str
    suppress_comment: str
