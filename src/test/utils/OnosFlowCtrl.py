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
from scapy.all import *
from OnosCtrl import OnosCtrl
import fcntl, socket, struct

def get_mac(iface = 'ovsbr0', pad = 4):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15]))
    except:
        info = ['0'] * 24
    return '0'*pad + ''.join(['%02x' %ord(char) for char in info[18:24]])

class OnosFlowCtrl:

    auth = ('karaf', 'karaf')
    controller = os.getenv('ONOS_CONTROLLER_IP') or 'localhost'
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
                  mpls=""):
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

    @classmethod
    def get_flows(cls, device_id):
        return OnosCtrl.get_flows(device_id)

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
        flows = self.get_flows(deviceId)
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
                log.info('Successfully POSTED flow for device %s' %str(deviceId))
                return True
            else:
                log.info('Post flow for device %s failed with status %d' %(str(deviceId), 
                                                                           response.status_code))
                return False
        else:
            log.error('Flow post request returned with status %d' %response.status_code)

        return False
