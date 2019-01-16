*** Settings ***
Documentation    Scale up models in a SEBA deployment with no backends
Library           KafkaLibrary
Library           RequestsLibrary
Library           HttpLibrary.HTTP
Library           Collections
Library           String
Library           OperatingSystem
Library           ../../Framework/utils/utils.py
Resource          ../../Framework/utils/utils.robot
Suite Setup       Setup
Suite Teardown    Teardown

*** Variables ***
${xos_chameleon_url}    localhost
${xos_chameleon_port}   30006
${olt_device_id}        of:robot_test
${pon_port_id}          1

${scale_size}           5

${WHITELIST_PATHFILE}      ${CURDIR}/data/whitelist.json

*** Test Cases ***
Create Whitelist
    [Documentation]     Just do something
    ${res} =   CORD Get    /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries
    ${jsondata} =    To Json    ${res.content}
    ${length} =    Get Length    ${jsondata['items']}
    ${total} =      Convert To Integer   ${scale_size}
    Should Be Equal    ${length}    ${total}



*** Keywords ***
Setup
#    Connect Producer    ${cord_kafka}:9092    onu.events
#    Connect Producer    ${cord_kafka}:9092    authentication.events
#    Connect Producer    ${cord_kafka}:9092    dhcp.events
    ${auth} =    Create List    admin@opencord.org    letmein
    ${HEADERS}    Create Dictionary    Content-Type=application/json
    Create Session    XOS    http://${xos_chameleon_url}:${xos_chameleon_port}    auth=${AUTH}    headers=${HEADERS}
    Store Data
    Setup Whitelist

Teardown
    [Documentation]    Delete all models created
    Log     Teardown
    Clean Whitelist
    Delete All Sessions
#    CORD Get    /xosapi/v1/rcord/rcordsubscribers
#    CORD Delete    /xosapi/v1/rcord/rcordsubscribers    ${subscriber_id}
#    Wait Until Keyword Succeeds    60s    5s    CORD Delete    /xosapi/v1/volt/oltdevices    ${oltdevice_id}
#    CORD Delete    /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries    ${whitelist_entry2_id}

Setup Whitelist
    [Documentation]     Create a whitelist for the tests
    : FOR    ${INDEX}    IN RANGE    0    ${scale_size}
    \   ${serial_number} =      Catenate    SEPARATOR=    MOCK0000000     ${INDEX}
    \   ${whitelist_entry} =    Create Dictionary   serial_number=${serial_number}  device_id=${olt_device_id}   pon_port_id=${pon_port_id}  owner_id=${attworkflowservice_id}
    \   Log     ${whitelist_entry}
    \   CORD Post   /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries    ${whitelist_entry}

Clean Whitelist
    [Documentation]     Clean the whitelist
    ${res} =    CORD Get    /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries
    ${jsondata} =    To Json    ${res.content}
    ${length} =    Get Length    ${jsondata['items']}
    :FOR    ${INDEX}    IN RANGE    0    ${length}
    \   ${ELEMENT} =    Get From List    ${jsondata['items']}    ${INDEX}
    \   ${id}=    Get From Dictionary    ${ELEMENT}    id
    \   CORD Delete     /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries    ${id}

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
    [Return]    ${resp}

CORD Delete
    [Documentation]    Make a DELETE call to the CORD controller
    [Arguments]    ${service}    ${data_id}
    ${resp}=    Delete Request    XOS    uri=${service}/${data_id}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    [Return]    ${resp}