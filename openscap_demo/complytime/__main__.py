# Copyright (c) 2024 Red Hat, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
Run C2P with the OpenSCAP plugin
"""


import fire  # type: ignore
from complytime.complytime import ComplyTimeClient


def init() -> None:
    """Initialize complytime"""
    address = "unix:///tmp/example.sock"
    sample_client = ComplyTimeClient(address)
    fire.Fire(sample_client)


if __name__ == "__main__":
    init()
