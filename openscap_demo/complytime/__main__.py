# Copyright (c) 2024 Red Hat, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
Run C2P with the OpenSCAP plugin
"""


import fire  # type: ignore
from complytime.complytime import ComplyTimePrototype


def init() -> None:
    """Initialize complytime"""
    fire.Fire(ComplyTimePrototype)


if __name__ == "__main__":
    init()
