import json
from typing import Any


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, set):
            return list(o)
        else:
            return json.JSONEncoder.default(self, o)
