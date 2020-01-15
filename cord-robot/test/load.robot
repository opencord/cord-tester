*** Settings ***
Documentation     Library for ONOS Functions
Library           CORDRobot
Library   ImportResource  resources=CORDRobot

*** Test Cases ***
Test list resources
    [Documentation]    Lists all resources loaded
    ${res}=    ImportResource.external_resources
    Log To Console    ${res}

Test Validate Loading of CORDrobot
    [Documentation]    Validates that CORDRobot can be invoked
    [Setup]    None
    Execute ONOS CLI Command    localhost     8080    versions
