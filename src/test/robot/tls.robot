***settings ***
Documentation  Run Cord verification test cases
Resource  cord_resource.robot
Suite Setup  Cord Setup
Suite Teardown  Cord Teardown

*** Test Cases ***

Verify ONOS AAA Authentication Functionality 1
  [Documentation]  Test ONOS AAA TLS Authentication
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 2
  [Documentation]  Test ONOS AAA TLS Authentication with no certificates
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_with_no_cert
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 3
  [Documentation]  Test ONOS AAA TLS Authentication with invalid certificates
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_with_invalid_cert
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 4
  [Documentation]  Test ONOS AAA TLS Authentication for multiple users with same valid certificates
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_Nusers_with_same_valid_cert
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 5
  [Documentation]  Test ONOS AAA TLS Authentication with invalid session ID
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_invalid_session_id
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 6
  [Documentation]  Test ONOS AAA TLS Authentication with random gmt unix time
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_random_gmt_unix_time
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 7
  [Documentation]  Test ONOS AAA TLS Authentication with invalid content type
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_invalid_content_type
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 8
  [Documentation]  Test ONOS AAA TLS Authentication with invalid  record fragmement length
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_invalid_record_fragment_length
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 9
  [Documentation]  Test ONOS AAA TLS Authentication with invalid Id in identifier response packet
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_with_invalid_id_in_identifier_response_packet
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 10
  [Documentation]  Test ONOS AAA TLS Authentication with invalid ID in client hello packet
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_with_invalid_id_in_client_hello_packet
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 11
  [Documentation]  Send IGMP join to ONOS and verify data traffic
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_without_sending_client_hello
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 12
  [Documentation]  Test ONOS AAA TLS Authentication with the app  deactivate
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_aaa_app_deactivate
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 13
  [Documentation]  Test ONOS AAA TLS Authentication with incorrect cipher suite length
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_incorrect_cipher_suite_length_field
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 14
  [Documentation]  Test ONOS AAA TLS Authentication with incorrect compression length field
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_incorrect_compression_methods_length_field
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 15
  [Documentation]  Test ONOS AAA TLS Authentication with invalid source mac broadcast
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_invalid_source_mac_broadcast
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 16
  [Documentation]  Test ONOS AAA TLS Authentication with invalid source mac multicast
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_invalid_source_mac_multicast
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 17
  [Documentation]  Test ONOS AAA TLS Authentication with invalid source mac zeros
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_invalid_source_mac_zero
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 18
  [Documentation]  Test ONOS AAA TLS Authentication with redius server restart
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_restart_radius_server
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 19
  [Documentation]  Test ONOS AAA TLS Authentication with incorrect handshake type in client hello
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_with_incorrect_handshake_type_client_hello
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 20
  [Documentation]  Test ONOS AAA TLS Authentication with incorrect handshake type certificate request
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_with_incorrect_handshake_type_certificate_request
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 21
  [Documentation]  Test ONOS AAA TLS Authentication with incorrect tls record certificate request
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_with_incorrect_tlsrecord_certificate_request
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 22
  [Documentation]  Test ONOS AAA TLS Authentication with incorrect handshake length client hello
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_invalid_handshake_length_client_hello
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 23
  [Documentation]  Test ONOS AAA TLS Authentication with client key exchange replace with server key exchange
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_clientkeyex_replace_with_serverkeyex
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 24
  [Documentation]  Test ONOS AAA TLS Authentication for 1k different macs
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_1k_with_diff_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Authentication Functionality 25
  [Documentation]  Test ONOS AAA TLS Authentication for 5k different macs
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_5k_with_diff_mac
  Should Be Equal As Integers  ${rc}  0

