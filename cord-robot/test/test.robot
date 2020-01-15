*** Settings ***
Documentation     Tests for the CORDRobot library
Library           OperatingSystem
Library           CORDRobot
Library           ImportResource    resources=CORDRobot

*** Test Cases ***
Test list resources
    [Documentation]    Lists all resources loaded
    ${res}=    ImportResource.external_resources
    Log To Console    ${res}

Test loading of CORDRobot Python Functions
    [Documentation]    Check if __init__.py function work
    ${ver}=    CR_Version
    Log To Console    ${ver}

Test loading of testCaseUtils
    [Documentation]    Check if testCaseUtils.py functions work
    ${fields}=    CORDRobot.parse_fields    foo,bar    ,
    Log To Console    ${fields}

Test loading of CORDDictUtils
    [Documentation]    Check if CORDDictUtils functions work
    ${json}=    CORDRobot.jsonToList    ${CURDIR}/test.json    test
    Log To Console    ${json}

Test loading of restApi
    [Documentation]    Check if restApi functions work
    ${url1}=    CORDRobot.getURL    CORE_NODES
    Log To Console    ${url1}
    Set Environment Variable    CORDROBOT_TEST    /cord_robot_test/
    ${url2}=    CORDRobot.getURL    CORDROBOT_TEST
    Log To Console    ${url2}

Test Validate Loading of CORDRobot Resources
    [Documentation]    Validates that the .resource files distributed by
    ...    CORDRobot can be invoked
    Execute Command Locally    echo "Able to run Execute Commnd Locally"
