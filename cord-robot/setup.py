#!/usr/bin/env python

# Copyright 2020-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
from setuptools import setup
from shutil import copyfile

LIBRARY_NAME = "CORDRobot"


def version():
    # Copy VERSION file of parent to module directory if not found
    version_path = os.path.join(LIBRARY_NAME, "VERSION")
    if not os.path.exists(version_path):
        copyfile("../VERSION", version_path)
    with open(version_path) as f:
        return f.read().strip()


def parse_requirements(filename):
    # parse a requirements.txt file, allowing for blank lines and comments
    requirements = []
    for line in open(filename):
        if line and not line.startswith("#"):
            requirements.append(line)
    return requirements


setup(
    name="cord-robot",
    version=version(),
    description="CORD Project Robot Libraries and common Resources",
    author="CORD Developers",
    include_package_data=True,
    packages=[LIBRARY_NAME],
    package_data={
        LIBRARY_NAME: ["rf-resources/*.resource", "VERSION"]
    },
    install_requires=parse_requirements("requirements.txt"),
)
