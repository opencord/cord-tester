*** Settings ***
Documentation     Library for ONOS Functions
Library           CORDRobot
Library           ImportResource    resources=CORDRobot

*** Test Cases ***
Test list resources
    [Documentation]    Lists all resources loaded
    ${res}=    ImportResource.external_resources
    Log To Console    ${res}

Test Validate Loading of CORDRobot Python Functions
    [Documentation]    Validates that the python files distributed by
    ...    CORDRobot can be invoked
    [Setup]    None
    ${ver}=    Version
    Log To Console    ${ver}

Test Validate Loading of CORDRobot Resources
    [Documentation]    Validates that the .resource files distributed by
    ...    CORDRobot can be invoked
    [Setup]    None
    Execute Command Locally    echo "Able to run Execute Commnd Locally"

