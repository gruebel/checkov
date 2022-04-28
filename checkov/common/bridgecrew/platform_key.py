from __future__ import annotations

import hashlib
import os
from pathlib import Path

import diskcache

home = str(Path.home())
bridgecrew_dir = "{}/.bridgecrew".format(home)
bridgecrew_file = "{}/credentials".format(bridgecrew_dir)


def persist_key(key):
    if not os.path.exists(bridgecrew_dir):
        os.makedirs(bridgecrew_dir)
    with open(bridgecrew_file, "w") as f:
        f.write(key)


def read_key():
    key = None
    if os.path.exists(bridgecrew_file):
        with open(bridgecrew_file, "r") as f:
            key = f.readline()
    return key


def setup_cache() -> diskcache.Cache:
    cache_dir = Path(bridgecrew_dir) / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache = diskcache.Cache(str(cache_dir))

    return cache


def sha256sum(filename: Path, buffer_size: int = 128 * 1024) -> str:
    # h = hashlib.sha256()
    # buffer = bytearray(buffer_size)
    # # using a memoryview so that we can slice the buffer without copying it
    # buffer_view = memoryview(buffer)
    # with open(filename, 'rb', buffering=0) as f:
    #     while True:
    #         n = f.readinto(buffer_view)
    #         if not n:
    #             break
    #         h.update(buffer_view[:n])
    # return h.hexdigest()
    return hashlib.sha256(filename.read_bytes()).hexdigest()
