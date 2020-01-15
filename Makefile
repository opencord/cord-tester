# Copyright 2017-present Open Networking Foundation
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

# use bash for pushd/popd, and to fail quickly. virtualenv's activate
# has undefined variables, so no -u
SHELL     := bash -e -o pipefail

WORKSPACE ?= $(HOME)
VERSION   ?= $(shell cat ./VERSION)

# Robot confiig
ROBOT_FILE                      ?=
ROBOT_DIR                       ?=
ROBOT_DEBUG_LOG_OPT             ?=
ROBOT_MISC_ARGS                 ?=
ROBOT_TEST_TAGS                 ?= stable

# Robot Job definitions
siab-robot: ROBOT_FILE := SIAB.robot
siab-robot: ROBOT_DIR := src/test/cord-api/Tests/WorkflowValidations
siab-robot: ROBOT_MISC_ARGS += --removekeywords wuks -e notready $(ROBOT_DEBUG_LOG_OPT) -i $(ROBOT_TEST_TAGS) -v VOLTHA_DIR:$(WORKSPACE)/cord/incubator/voltha  -v SUBSCRIBER_FILENAME:SIABSubscriberLatest -v WHITELIST_FILENAME:SIABWhitelistLatest -v OLT_DEVICE_FILENAME:SIABOLT0Device
siab-robot: seba-robot

seba-robot: cord_venv
	source ./$</bin/activate ; set -u ;\
  cd $(ROBOT_DIR) ;\
  robot -V $(ROBOT_FILE) $(ROBOT_MISC_ARGS)

# self-test, lint, and setup targets
ROBOT_LINT_ARGS ?= --verbose \
                   --configure LineTooLong:120 -e LineTooLong \
                   -e TooManyTestSteps \
                   -e TooManyTestCases \
                   --configure TooFewTestSteps:1 \
                   --configure TooFewKeywordSteps:1 \
                   -e FileTooLong \
                   -e TrailingWhitespace

PYTHON_FILES := $(shell find ./src -name *.py -print)
ROBOT_FILES  := $(shell find ./src -name *.robot -print)
YAML_FILES   := $(shell find ./src -type f \( -name *.yaml -o -name *.yml \) -print)
JSON_FILES   := $(shell find ./src -name *.json -print)
JENKINSFILES := $(shell find . -type f -name 'Jenkinsfile*' -print)

# virtualenv for the robot tools
cord_venv:
	virtualenv -p python3 $@ ;\
  source ./$@/bin/activate ;\
  pip install -r requirements.txt ;\
  pip install -e cord-robot

test: cord-robot-test

cord-robot-test:
	cd cord-robot; tox

lint: lint-robot lint-python lint-json # disabled: lint-yaml lint-jenkins

lint-robot: cord_venv
	source ./$</bin/activate ; set -u ;\
  rflint $(ROBOT_LINT_ARGS) $(ROBOT_FILES)

# check deps for format and python3 cleanliness
lint-python: cord_venv
	source ./$</bin/activate ; set -u ;\
  pylint --py3k $(PYTHON_FILES) ;\
  flake8 --max-line-length=99 --count $(PYTHON_FILES)

lint-yaml: cord_venv
	source ./$</bin/activate ; set -u ;\
  yamllint -s $(YAML_FILES)

lint-json: cord_venv
	source ./$</bin/activate ; set -u ;\
  for jsonfile in $(JSON_FILES); do \
    echo "Validating json file: $$jsonfile" ;\
    python -m json.tool $$jsonfile > /dev/null ;\
  done

# only works on declarative pipeline Jenkinsfiles
lint-jenkins:
	./scripts/jflint.sh $(JENKINSFILES)

# tidy target will be more useful once issue with removing leading comments
# is resolved: https://github.com/robotframework/robotframework/issues/3263
tidy-robot: cord_venv
	source ./$</bin/activate ; set -u ;\
  python -m robot.tidy --inplace $(ROBOT_FILES);

## Variables for gendocs
TEST_SOURCE := $(wildcard tests/*/*.robot)
TEST_BASENAME := $(basename $(TEST_SOURCE))
TEST_DIRS := $(dir $(TEST_SOURCE))

LIB_SOURCE := $(wildcard libraries/*.robot)
LIB_BASENAME := $(basename $(LIB_SOURCE))
LIB_DIRS := $(dir $(LIB_SOURCE))

.PHONY: gendocs lint test
# In future explore use of --docformat REST - integration w/Sphinx?
gendocs: cord_venv
	source ./$</bin/activate ; set -u ;\
  mkdir -p $@ ;\
  for dir in ${LIB_DIRS}; do mkdir -p $@/$$dir; done;\
  for dir in ${LIB_BASENAME}; do\
    python -m robot.libdoc --format HTML $$dir.robot $@/$$dir.html ;\
  done ;\
  for dir in ${TEST_DIRS}; do mkdir -p $@/$$dir; done;\
  for dir in ${TEST_BASENAME}; do\
    python -m robot.testdoc $$dir.robot $@/$$dir.html ;\
  done

clean:
	find . -name output.xml -print

clean-all: clean
	rm -rf cord_venv gendocs cord-robot/CORDRobot/VERSION

