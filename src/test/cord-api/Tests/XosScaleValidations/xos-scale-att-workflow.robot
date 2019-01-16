*** Settings ***
Documentation    Scale up models in a SEBA deployment with no backends
Resource         utils.robot
Library           KafkaLibrary
Library           RequestsLibrary
Library           HttpLibrary.HTTP
Library           Collections
Library           String
Library           OperatingSystem
Suite Setup       Setup
Suite Teardown    Teardown

*** Variables ***
${xos_chameleon_url}    localhost
${xos_chameleon_port}   30007

*** Test Cases ***
Create Whitelist
    [Tags]    DEBUG
    [Documentation] Create a whitelist for the tests
    ${whitelist} = CORD Get    /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries
    Log ${whitelist}


*** Keywords ***
Setup
    Connect Producer    ${cord_kafka}:9092    onu.events
    Connect Producer    ${cord_kafka}:9092    authentication.events
    Connect Producer    ${cord_kafka}:9092    dhcp.events
    ${auth} =    Create List    admin@opencord.org    letmein
    ${HEADERS}    Create Dictionary    Content-Type=application/json
    Create Session    ${server_ip}    http://${server_ip}:${server_port}    auth=${AUTH}    headers=${HEADERS}

Teardown
    [Documentation]    Delete all models created
#    CORD Get    /xosapi/v1/rcord/rcordsubscribers
#    CORD Delete    /xosapi/v1/rcord/rcordsubscribers    ${subscriber_id}
#    Wait Until Keyword Succeeds    60s    5s    CORD Delete    /xosapi/v1/volt/oltdevices    ${oltdevice_id}
#    CORD Delete    /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries    ${whitelist_entry2_id}

CORD Get
    [Documentation]    Make a GET call to XOS
    [Arguments]    ${service}
    ${resp}=    Get Request    ${server_ip}    ${service}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    [Return]    ${resp}

CORD Post
    [Documentation]    Make a POST call to XOS
    [Arguments]    ${service}    ${data}
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    Post Request    ${server_ip}    uri=${service}    data=${data}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    ${id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${id}
    [Return]    ${resp}