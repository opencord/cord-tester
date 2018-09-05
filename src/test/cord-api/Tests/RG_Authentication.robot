*** Settings ***
Documentation     Test suite for validating E2E connectivity with RG Authentication
Suite Setup       Setup
Library           Collections
Library           String
Library           OperatingSystem
Library           XML
Library           RequestsLibrary
Library           ../Framework/utils/utils.py
Resource          ../Framework/utils/utils.robot
Library           ../Framework/restApi.py
Variables          ../Properties/RestApiProperties.py

*** Variables ***
${src_ip}         X.X.X.X
${src_gateway}    X.X.X.X
${src_user}       user
${src_pass}       pass
${dst_ip}         X.X.X.X
${dst_user}       user
${dst_pass}       pass
${dst_gateway}    X.X.X.X
${dst_host_ip}    X.X.X.X
${iface}          eth1

*** Test Cases ***
Validate Initial Subscriber State
    [Documentation]    Validate that after a subscriber has been configured, it's status is in "awaiting-auth"
    Check Subscriber State    awaiting-auth

Test Initial Ping
    [Documentation]    Validate that pings fail when authentication has not been requested/suceeded
    Wait Until Keyword Succeeds    60s    2s    Test Ping    FAIL    ${src_ip}    ${src_user}    ${src_pass}    ${dst_host_ip}

Send EAPOL Authentication Request
    [Documentation]    Send eapol auth request via wpa_supplicant client. request packet exists on source host.
    Send Client Command    ${src_ip}    ${src_user}    ${src_pass}    sudo wpa_supplicant -i ${iface} -Dwired -c /etc/wpa_supplicant/wpa_supplicant.conf

Validate Subscriber State Enabled
    [Documentation]    Validate that after a subscriber state changes after approved auth request
    Wait Until Keyword Succeeds    120s    2s    Check Subscriber State    enabled

Test Pre-DHCP Request Ping
    [Documentation]    Validate that pings fail when an ip address has not been requested via dhcp
    Wait Until Keyword Succeeds    60s    2s    Test Ping    FAIL    ${src_ip}    ${src_user}    ${src_pass}    ${dst_host_ip}

Send DHCP Request
    [Documentation]    Send a dhcp request to the dhcp server running on the destination host
    Send Client Command    ${src_ip}    ${src_user}    ${src_pass}    sudo echo 'nameserver 192.168.0.1' > /etc/resolv.conf
    Send Client Command    ${src_ip}    ${src_user}    ${src_pass}    sudo dhclient ${iface}
    Send Client Command    ${src_ip}    ${src_user}    ${src_pass}    sudo route add default gw 192.168.0.1 ${iface}
    ##Add check here to validate an ip in 192.168.0.0/24 range has been assigned

Test Final Ping
    [Documentation]    Validate that pings pass when authentication has suceeded
    Wait Until Keyword Succeeds    60s    2s    Test Ping    PASS    ${src_ip}    ${src_user}    ${src_pass}    ${dst_host_ip}

Send EAPOL Denied Request
    [Documentation]    Send eapol auth denied request via wpa_supplicant client. request packet exists on source host.
    [Tags]    notready
    Send Client Command    ${src_ip}    ${src_user}    ${src_pass}    sudo wpa_supplicant -i ${iface} -Dwired -c /etc/wpa_supplicant/wpa_supplicant_denied.conf

Validate Subscriber State Failed
    [Documentation]    Validate that after a subscriber state changes after denied auth request
    [Tags]    notready
    Wait Until Keyword Succeeds    120s    2s    Check Subscriber State    auth-failed

Test Ping Fail
    [Documentation]    Validate that pings fail when authentication has not been denied
    [Tags]    notready
    Wait Until Keyword Succeeds    60s    2s    Test Ping    FAIL    ${src_ip}    ${src_user}    ${src_pass}    ${dst_host_ip}

Re-Authenticate EAPOL Request
    [Documentation]    Send eapol auth request via wpa_supplicant client. request packet exists on source host.
    [Tags]    notready
    Send Client Command    ${src_ip}    ${src_user}    ${src_pass}    sudo wpa_supplicant -i ${iface} -Dwired -c /etc/wpa_supplicant/wpa_supplicant.conf

Validate Subscriber State Re-Enabled
    [Documentation]    Validate that after a subscriber state re-enabled after approved auth request
    [Tags]    notready
    Wait Until Keyword Succeeds    120s    2s    Check Subscriber State    enabled

Test Ping PASS Again
    [Documentation]    Validate that pings pass when authentication has been re-sent
    Wait Until Keyword Succeeds    60s    2s    Test Ping    PASS    ${src_ip}    ${src_user}    ${src_pass}    ${dst_host_ip}

*** Keywords ***
Setup
    ${AUTH} =    Create List    admin@opencord.org    letmein
    ${HEADERS}    Create Dictionary    Content-Type=application/json
    Create Session    ${SERVER_IP}    http://${SERVER_IP}:${SERVER_PORT}    auth=${AUTH}    headers=${HEADERS}

Send Client Command
    [Arguments]    ${ip}    ${user}    ${pass}    ${cmd}    ${prompt}=$    ${prompt_timeout}=60s
    ${conn_id}=    SSHLibrary.Open Connection    ${ip}    prompt=${prompt}    timeout=${prompt_timeout}
    SSHLibrary.Login    ${user}    ${pass}
    SSHLibrary.Write    sudo ${cmd}
    Read Until    [sudo] password for ${user}:
    SSHLibrary.Write    ${pass}
    ${result}=    Read Until    ${prompt}
    SSHLibrary.Close Connection

Check Subscriber State
    [Arguments]    ${expected_status}
    ${resp}=    Get Request    ${SERVER_IP}    /xosapi/v1/rcord/rcordsubscribers/1
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    ${status}=    Get Json Value    ${resp.content}    /status
    Should Be Equal As Strings    ${status}    ${expected_status}