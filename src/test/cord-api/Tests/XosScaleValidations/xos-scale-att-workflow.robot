*** Settings ***
Documentation    Scale up models in a SEBA deployment with no backends
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
${xos_chameleon_port}   30006

${WHITELIST_PATHFILE}      ${CURDIR}/data/whitelist.json

*** Test Cases ***
Create Whitelist
    [Documentation]     Create a whitelist for the tests
    ${AttWhiteListList}=    utils.jsonToList    ${WHITELIST_PATHFILE}   AttWhiteListInfo
    Log     ${AttWhiteListList}



*** Keywords ***
Setup
#    Connect Producer    ${cord_kafka}:9092    onu.events
#    Connect Producer    ${cord_kafka}:9092    authentication.events
#    Connect Producer    ${cord_kafka}:9092    dhcp.events
    ${auth} =    Create List    admin@opencord.org    letmein
    ${HEADERS}    Create Dictionary    Content-Type=application/json
    Create Session    XOS    http://${xos_chameleon_url}:${xos_chameleon_port}    auth=${AUTH}    headers=${HEADERS}
    Store Data

Teardown
    [Documentation]    Delete all models created
    Log     Teardown
    Delete All Sessions
#    CORD Get    /xosapi/v1/rcord/rcordsubscribers
#    CORD Delete    /xosapi/v1/rcord/rcordsubscribers    ${subscriber_id}
#    Wait Until Keyword Succeeds    60s    5s    CORD Delete    /xosapi/v1/volt/oltdevices    ${oltdevice_id}
#    CORD Delete    /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries    ${whitelist_entry2_id}

Store Data
    [Documentation]     Store all the ids needed for the test to work
    ${resp}=    CORD Get    /xosapi/v1/att-workflow-driver/attworkflowdriverservices
    ${jsondata}=    To Json    ${resp.content}
    ${attworkflowservice}=    Get From List    ${jsondata['items']}    0
    ${attworkflowservice_id}=    Get From Dictionary    ${attworkflowservice}    id
    Set Suite Variable    ${attworkflowservice_id}

CORD Get
    [Documentation]    Make a GET call to XOS
    [Arguments]    ${service}
    ${resp}=    Get Request    XOS    ${service}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    [Return]    ${resp}

CORD Post
    [Documentation]    Make a POST call to XOS
    [Arguments]    ${service}    ${data}
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    Post Request    XOS    uri=${service}    data=${data}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    ${id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${id}
    [Return]    ${resp}