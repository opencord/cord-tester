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

seba-robot: venv_cord
	source ./$</bin/activate ; set -u ;\
  cd $(ROBOT_DIR) ;\
  robot -V $(ROBOT_FILE) $(ROBOT_MISC_ARGS)

# self-test, lint, and setup targets
ROBOT_LINT_ARGS ?= --verbose \
                   --configure LineTooLong:120 \
                   --warning TooManyTestSteps \
                   --warning TooManyTestCases \
                   --configure TooFewTestSteps:1 \
                   --configure TooFewKeywordSteps:1 \
                   --warning FileTooLong \
                   --warning TrailingWhitespace \
                   --warning RequireKeywordDocumentation \
                   --warning RequireTestDocumentation \
                   --warning DuplicateTestNames

PYTHON_FILES := $(shell find ./src -name *.py -print)
ROBOT_FILES  := $(shell find ./src -name *.robot -print)
YAML_FILES   := $(shell find . -type f \( -name *.yaml -o -name *.yml \) -print)
JSON_FILES   := $(shell find ./src -name *.json -print)
JENKINSFILES := $(shell find . -type f -name 'Jenkinsfile*' -print)

# virtualenv for the robot tools
venv_cord:
	virtualenv -p python3 $@ ;\
  source ./$@/bin/activate ;\
  pip install -r requirements.txt ;\
  pip install -e cord-robot

# cord-robot is totally deprecated, removing.
test:

# virtualenv for the robot tools
# VOL-2724 Invoke pip via python3 to avoid pathname too long on QA jobs
vst_venv:
	virtualenv -p python3 $@ ;\
	source ./$@/bin/activate ;\
	python -m pip install -r requirements.txt

lint: lint-robot lint-python lint-yaml lint-json

lint-robot: vst_venv
	source ./$</bin/activate ; set -u ;\
	rflint $(ROBOT_LINT_ARGS) $(ROBOT_FILES)

# check deps for format and python3 cleanliness
lint-python: vst_venv
	source ./$</bin/activate ; set -u ;\
	pylint --py3k $(PYTHON_FILES) ;\
	flake8 --max-line-length=119 --count $(PYTHON_FILES)

lint-yaml: vst_venv
	source ./$</bin/activate ; set -u ;\
  yamllint \
  -d "{extends: default, rules: {line-length: {max: 119}}}" \
  -s $(YAML_FILES)

lint-json: vst_venv
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
tidy-robot: vst_venv
	source ./$</bin/activate ; set -u ;\
	python -m robot.tidy --inplace $(ROBOT_FILES);

## Variables for gendocs
TEST_SOURCE := $(wildcard src/test/cord-api/Tests/*/*.robot)
TEST_BASENAME := $(basename $(TEST_SOURCE))
TEST_DIRS := $(dir $(TEST_SOURCE))

PYLIB_SOURCE := $(filter-out cord-robot/CORDRobot/__init__.py, $(wildcard cord-robot/CORDRobot/*.py))
PYLIB_BASENAME := $(basename $(PYLIB_SOURCE))
PYLIB_DIRS := $(dir $(PYLIB_SOURCE))

RESOURCE_SOURCE := $(wildcard cord-robot/CORDRobot/rf-resources/*.resource)
RESOURCE_BASENAME := $(basename $(RESOURCE_SOURCE))
RESOURCE_DIRS := $(dir $(RESOURCE_SOURCE))

.PHONY: gendocs lint test
gendocs: venv_cord
	source ./$</bin/activate ; set -u ;\
  mkdir -p $@ ;\
  for dir in ${PYLIB_DIRS}; do mkdir -p $@/$$dir; done;\
  for dir in ${PYLIB_BASENAME}; do\
    python -m robot.libdoc --format HTML $$dir.py $@/$$dir.html ;\
  done ;\
  for dir in ${RESOURCE_DIRS}; do mkdir -p $@/$$dir; done;\
  for dir in ${RESOURCE_BASENAME}; do\
    python -m robot.libdoc --format HTML $$dir.resource $@/$$dir.html ;\
  done ;\
  for dir in ${TEST_DIRS}; do mkdir -p $@/$$dir; done;\
  for dir in ${TEST_BASENAME}; do\
    python -m robot.testdoc $$dir.robot $@/$$dir.html ;\
  done

clean:
	find . -name output.xml -print

clean-all: clean
	rm -rf venv_cord gendocs cord-robot/CORDRobot/VERSION cord-robot/dist/*

