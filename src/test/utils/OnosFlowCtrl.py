#
# Copyright 2016-present Ciena Corporation
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
#
import json
import requests
import os,sys,time
from nose.tools import *
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from OnosCtrl import OnosCtrl, get_controller
from CordTestUtils import log_test

class OnosFlowCtrl:

    auth = ('karaf', 'karaf')
    controller = get_controller()
    cfg_url = 'http://%s:8181/onos/v1/flows/' %(controller)

    def __init__( self,
                  deviceId,
                  appId=0,
                  ingressPort="",
                  egressPort="",
                  ethType="",
                  ethSrc="",
                  ethDst="",
                  vlan="",
                  ipProto="",
                  ipSrc=(),
                  ipDst=(),
                  tcpSrc="",
                  tcpDst="",
                  udpDst="",
                  udpSrc="",
                  mpls="",
		  dscp="",
		  icmpv4_type="",
		  icmpv4_code="",
		  icmpv6_type="",
		  icmpv6_code="",
		  ipv6flow_label="",
		  ecn="",
		  ipv6_target="",
		  ipv6_sll="",
		  ipv6_tll="",
		  ipv6_extension="",
		  controller=None):
        self.deviceId = deviceId
        self.appId = appId
        self.ingressPort = ingressPort
        self.egressPort = egressPort
        self.ethType = ethType
        self.ethSrc = ethSrc
        self.ethDst = ethDst
        self.vlan = vlan
        self.ipProto = ipProto
        self.ipSrc = ipSrc
        self.ipDst = ipDst
        self.tcpSrc = tcpSrc
        self.tcpDst = tcpDst
        self.udpDst = udpDst
        self.udpSrc = udpSrc
        self.mpls = mpls
        self.dscp = dscp
	self.icmpv4_type = icmpv4_type
	self.icmpv4_code = icmpv4_code
	self.icmpv6_type = icmpv6_type
	self.icmpv6_code = icmpv6_code
	self.ipv6flow_label = ipv6flow_label
	self.ecn = ecn
	self.ipv6_target = ipv6_target
	self.ipv6_sll = ipv6_sll
	self.ipv6_tll = ipv6_tll
	self.ipv6_extension = ipv6_extension
	if controller is not None:
		self.controller=controller
		self.cfg_url = 'http://%s:8181/onos/v1/flows/' %(self.controller)

    @classmethod
    def get_flows(cls, device_id,controller=None):
        return OnosCtrl.get_flows(device_id,controller=controller)

    def addFlow(self):
        """
        Description:
            Creates a single flow in the specified device
        Required:
            * deviceId: id of the device
        Optional:
            * ingressPort: port ingress device
            * egressPort: port  of egress device
            * ethType: specify ethType
            * ethSrc: specify ethSrc ( i.e. src mac addr )
            * ethDst: specify ethDst ( i.e. dst mac addr )
            * ipProto: specify ip protocol
            * ipSrc: specify ip source address with mask eg. ip#/24
                as a tuple (type, ip#)
            * ipDst: specify ip destination address eg. ip#/24
                as a tuple (type, ip#)
            * tcpSrc: specify tcp source port
            * tcpDst: specify tcp destination port
        Returns:
            True for successful requests;
            False for failure/error on requests
        """
        flowJson = { "priority":100,
                     "isPermanent":"true",
                     "timeout":0,
                     "deviceId":self.deviceId,
                     "treatment":{"instructions":[]},
                     "selector": {"criteria":[]}}
        if self.appId:
            flowJson[ "appId" ] = self.appId

        if self.egressPort:
            flowJson[ 'treatment' ][ 'instructions' ].append( {
                    "type":"OUTPUT",
                    "port":self.egressPort } )
        if self.ingressPort:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":"IN_PORT",
                    "port":self.ingressPort } )
        if self.ethType:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":"ETH_TYPE",
                    "ethType":self.ethType } )
        if self.ethSrc:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":"ETH_SRC",
                    "mac":self.ethSrc } )
        if self.ethDst:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":"ETH_DST",
                    "mac":self.ethDst } )
        if self.vlan:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":"VLAN_VID",
                    "vlanId":self.vlan } )
        if self.mpls:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":"MPLS_LABEL",
                    "label":self.mpls } )
        if self.ipSrc:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":self.ipSrc[0],
                    "ip":self.ipSrc[1] } )
        if self.ipDst:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":self.ipDst[0],
                    "ip":self.ipDst[1] } )
        if self.tcpSrc:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":"TCP_SRC",
                    "tcpPort": self.tcpSrc } )
        if self.tcpDst:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":"TCP_DST",
                    "tcpPort": self.tcpDst } )
        if self.udpSrc:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":"UDP_SRC",
                    "udpPort": self.udpSrc } )
        if self.udpDst:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":"UDP_DST",
                    "udpPort": self.udpDst } )
        if self.ipProto:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":"IP_PROTO",
                    "protocol": self.ipProto } )
        if self.dscp:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":"IP_DSCP",
                    "ipDscp": self.dscp } )

        if self.icmpv4_type:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":'ICMPV4_TYPE',
                    "icmpType":self.icmpv4_type } )

        if self.icmpv6_type:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":'ICMPV6_TYPE',
                    "icmpv6Type":self.icmpv6_type } )

        if self.icmpv4_code:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":'ICMPV4_CODE',
                    "icmpCode": self.icmpv4_code } )

        if self.icmpv6_code:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":'ICMPV6_CODE',
                    "icmpv6Code": self.icmpv6_code } )

        if self.ipv6flow_label:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":'IPV6_FLABEL',
                    "flowLabel": self.ipv6flow_label } )

        if self.ecn:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":"IP_ECN",
                    "ipEcn": self.ecn } )

        if self.ipv6_target:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":'IPV6_ND_TARGET',
                    "targetAddress": self.ipv6_target } )

        if self.ipv6_sll:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":'IPV6_ND_SLL',
                    "mac": self.ipv6_sll } )

        if self.ipv6_tll:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":'IPV6_ND_TLL',
                    "mac": self.ipv6_tll } )


        if self.ipv6_extension:
            flowJson[ 'selector' ][ 'criteria' ].append( {
                    "type":'IPV6_EXTHDR',
                    "exthdrFlags": self.ipv6_extension } )




        return self.sendFlow( deviceId=self.deviceId, flowJson=flowJson)

    def removeFlow(self, deviceId, flowId):
        """
        Description:
            Remove specific device flow
        Required:
            str deviceId - id of the device
            str flowId - id of the flow
        Return:
            Returns True if successfully deletes flows, otherwise False
        """
        # NOTE: REST url requires the intent id to be in decimal form
        query = self.cfg_url + str( deviceId ) + '/' + str( int( flowId ) )
        response = requests.delete(query, auth = self.auth)
        if response:
            if 200 <= response.status_code <= 299:
                return True
            else:
                return False

        return True

    def findFlow(self, deviceId, **criterias):
        flows = self.get_flows(deviceId,controller=self.controller)
        match_keys = criterias.keys()
        matches = len(match_keys)
        num_matched = 0
        for f in flows:
            criteria = f['selector']['criteria']
            for c in criteria:
                if c['type'] not in match_keys:
                    continue
                match_key, match_val = criterias.get(c['type'])
                val = c[match_key]
                if val == match_val:
                    num_matched += 1
                if num_matched == matches:
                    return f['id']
        return None

    def sendFlow(self, deviceId, flowJson):
        """
        Description:
            Sends a single flow to the specified device. This function exists
            so you can bypass the addFLow driver and send your own custom flow.
        Required:
            * The flow in json
            * the device id to add the flow to
        Returns:
            True for successful requests
            False for error on requests;
        """
        url = self.cfg_url + str(deviceId)
        response = requests.post(url, auth = self.auth, data = json.dumps(flowJson) )
        if response.ok:
            if response.status_code in [200, 201]:
                log_test.info('Successfully POSTED flow for device %s' %str(deviceId))
                return True
            else:
                log_test.info('Post flow for device %s failed with status %d' %(str(deviceId),
                                                                           response.status_code))
                return False
        else:
            log_test.error('Flow post request returned with status %d' %response.status_code)

        return False
