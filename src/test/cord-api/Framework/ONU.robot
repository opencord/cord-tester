*** Settings ***
Documentation     Library to check the status in ONU List
Library           Collections
Library           String
Library           OperatingSystem
Library           XML
Library           RequestsLibrary
Library           utils/utils.py
Library           restApi.py

*** Keywords ***
ONU Status Check
    [Arguments]    ${onu_device}
    [Documentation]    Returns "operational_status" and "admin_status" of a particular ONU device from "onu device list"
    ${json_result}=    restApi.ApiGet    ONU_DEVICE
    Log    ${json_result}
    ${json_result_list}=    Get From dictionary    ${json_result}    items
    ${getJsonDict}=    utils.getDictFromListOfDict    ${json_result_list}    serial_number    ${onu_device}
    ${operational_status}=  Get From Dictionary    ${getJsonDict}   oper_status
    ${admin_status}=  Get From Dictionary    ${getJsonDict}   admin_state
    [Return]    ${operational_status}    ${admin_status} 

Create ONU Device
    [Arguments]    ${device_list}    ${list_index}
    [Documentation]    Sends a POST to create an att whitelist in XOS
    ${dlist} =    Get Variable Value    ${device_list}
    ${onu_dictionary}=    utils.listToDict    ${dlist}    ${list_index}
    ${api_result}=    restApi.ApiPost    ONU_DEVICE    ${onu_dictionary}
    Should Be True    ${api_result}

Retrieve ONU Device
    [Arguments]    ${serial_number}
    [Documentation]    Returns the onu device id based on the onu's serial number
    ${json_result}=    restApi.ApiGet    ONU_DEVICE
    Log    ${json_result}
    Log To Console    ${json_result}
    ${json_result_list}=    Get From dictionary    ${json_result}    items
    ${getJsonDict}=    utils.getDictFromListOfDict    ${json_result_list}    serial_number    ${serial_number}
    ${id}=    Get From Dictionary    ${getJsonDict}   id
    [Return]    ${id}

Delete ONU Device
    [Arguments]    ${id}
    [Documentation]    Sends a DELETE to delete an onu device in XOS
    ${api_result}=    restApi.ApiChameleonDelete    ONU_DEVICE    ${id}
    Should Be True    ${api_result}
