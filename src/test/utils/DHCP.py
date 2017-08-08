
# Copyright 2017-present Open Networking Foundation
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
from scapy.all import *
from CordTestUtils import log_test

conf.verb = 0 # Disable Scapy verbosity
conf.checkIPaddr = 0 # Don't check response packets for matching destination IPs

class DHCPTest:

    def __init__(self, seed_ip = '192.168.1.1', iface = 'veth0',lease_time=600):
        self.seed_ip = seed_ip
        self.seed_mac = self.ipToMac(self.seed_ip)
        self.iface = iface
	self.lease_time = lease_time
        self.mac_map = {}
        self.mac_inverse_map = {}
	self.bootpmac = None
	self.dhcpresp = None
	self.servermac = None
	self.return_option = None
	self.after_T2 = False
	self.send_different_option = None
        self.specific_lease = None

    def is_mcast(self, ip):
        mcast_octet = (atol(ip) >> 24) & 0xff
        return True if mcast_octet >= 224 and mcast_octet <= 239 else False

    def discover(self, mac = None, update_seed = False):
        '''Send a DHCP discover/offer'''

        if mac is None:
            mac = self.seed_mac
            if update_seed:
                self.seed_ip = self.incIP(self.seed_ip)
                self.seed_mac = self.ipToMac(self.seed_ip)
                mac = self.seed_mac

        chmac = self.macToChaddr(mac)
	#log_test.info('mac and chmac are %s %s'%(mac, chmac))
	self.bootpmac = chmac
        L2 = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
        L3 = IP(src="0.0.0.0", dst="255.255.255.255")
        L4 = UDP(sport=68, dport=67)
        L5 = BOOTP(chaddr=chmac)
        L6 = DHCP(options=[("message-type","discover"),"end"])
        resp = srp1(L2/L3/L4/L5/L6, filter="udp and port 68", timeout=10, iface=self.iface)
	#log_test.info('dhcp discover packet is %s'%(L2/L3/L4/L5/L6).show())
        self.dhcpresp = resp
	#log_test.info('discover response is %s'%resp.show())
        try:
            srcIP = resp.yiaddr
            serverIP = resp.siaddr
        except AttributeError:
            log_test.info("Failed to acquire IP via DHCP for %s on interface %s" %(mac, self.iface))
            return (None, None)

        subnet_mask = "0.0.0.0"
        for x in resp.lastlayer().options:
            if(x == 'end'):
                break
            op,val = x
            if(op == "subnet_mask"):
                subnet_mask = val
            elif(op == 'server_id'):
                server_id = val

        L5 = BOOTP(chaddr=chmac, yiaddr=srcIP)
        L6 = DHCP(options=[("message-type","request"), ("server_id",server_id),
                           ("subnet_mask",subnet_mask), ("requested_addr",srcIP), "end"])
        resp2 = srp1(L2/L3/L4/L5/L6, filter="udp and port 68", timeout=10, iface=self.iface)
	#log_test.info('request response is %s'%resp2.show())
        self.mac_map[mac] = (srcIP, serverIP)
        self.mac_inverse_map[srcIP] = (mac, serverIP)
        return (srcIP, serverIP)

    def only_discover(self, mac = None, desired = False, lease_time = False, lease_value=600, multiple = False):
        '''Send a DHCP discover'''

        if mac is None:
	    if multiple:
               mac = RandMAC()._fix()
	    else:
               mac = self.seed_mac


        chmac = self.macToChaddr(mac)
	self.bootpmac = chmac
        L2 = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
        L3 = IP(src="0.0.0.0", dst="255.255.255.255")
        L4 = UDP(sport=68, dport=67)
        L5 = BOOTP(chaddr=chmac)
	if desired:
		L6 = DHCP(options=[("message-type","discover"),("requested_addr",self.seed_ip),"end"])

	elif lease_time:
		L6 = DHCP(options=[("message-type","discover"),("lease_time",lease_value),"end"])

	else:
	        L6 = DHCP(options=[("message-type","discover"),"end"])
	#log_test.info('only discover packet is %s'%(L2/L3/L4/L5/L6).show())

        resp = srp1(L2/L3/L4/L5/L6, filter="udp and port 68", timeout=10, iface=self.iface)
	#log_test.info('discovery packet is %s'%(L2/L3/L4/L5/L6).show())
	if resp == None:
                return (None, None, mac, None)
	#log_test.info('only discover response is %s'%resp.show())

	self.dhcpresp = resp
        for x in resp.lastlayer().options:
            if(x == 'end'):
                break
            op,val = x
            if(op == "message-type"):

	    	if(val == 2):

			try:
            			srcIP = resp.yiaddr
            			serverIP = resp.siaddr
        		except AttributeError:
           			log_test.info("In Attribute error.")
            		 	log_test.info("Failed to acquire IP via DHCP for %s on interface %s" %(mac, self.iface))
                                return (None, None, None, None)

			if self.return_option:
				for x in resp.lastlayer().options:
        	    			if(x == 'end'):
                				break
	            			op,val = x

	        	    		if op == "lease_time":
						if self.return_option == 'lease':
							return (srcIP, serverIP, mac, val)

	        	    		elif op == "subnet_mask":
						if self.return_option == 'subnet':
							return (srcIP, serverIP, mac, val)
					elif op == "router":
						if self.return_option == 'router':
							return (srcIP, serverIP, mac, val)
					elif op == "broadcast_address":
						if self.return_option == 'broadcast_address':
							return (srcIP, serverIP, mac, val)
					elif op == "name_server":
						if self.return_option == 'dns':
							return (srcIP, serverIP, mac, val)


			else:
				return (srcIP, serverIP, mac, None)
		elif(val == 6):
			return (None, None, mac, None)


    def only_request(self, cip, mac, cl_reboot = False, lease_time = False, lease_value=600, renew_time = False, rebind_time = False, unicast = False):
        '''Send a DHCP offer'''

	subnet_mask = "0.0.0.0"
        for x in self.dhcpresp.lastlayer().options:
            	if(x == 'end'):
                	break
            	op,val = x
            	if(op == "subnet_mask"):
                	subnet_mask = val
            	elif(op == 'server_id'):
                	server_id = val

	if unicast and self.servermac:
        	L2 = Ether(dst=self.servermac, src=mac)
	        L3 = IP(src=cip, dst=server_id)
	else:
	        L2 = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
		if self.after_T2:
	        	L3 = IP(src=cip, dst="255.255.255.255")
		else:
		        L3 = IP(src="0.0.0.0", dst="255.255.255.255")
        L4 = UDP(sport=68, dport=67)

	if self.after_T2 == True:
        	L5 = BOOTP(chaddr=self.bootpmac, ciaddr = cip)
	else:

	        L5 = BOOTP(chaddr=self.bootpmac, yiaddr=cip)

	if cl_reboot or self.after_T2:
                L6 = DHCP(options=[("message-type","request"),("subnet_mask",subnet_mask), ("requested_addr",cip), "end"])
	elif self.send_different_option:
		if self.send_different_option == 'subnet':
	       		L6 = DHCP(options=[("message-type","request"),("server_id",server_id),
        	                   	("subnet_mask",'255.255.252.252'), ("requested_addr",cip), "end"])
		elif self.send_different_option == 'router':
	       		L6 = DHCP(options=[("message-type","request"),("server_id",server_id),
        	                   	("subnet_mask",subnet_mask), ("router",'1.1.1.1'), ("requested_addr",cip), "end"])
		elif self.send_different_option == 'broadcast_address':
	       		L6 = DHCP(options=[("message-type","request"),("server_id",server_id),
        	                   	("subnet_mask",subnet_mask), ("broadcast_address",'1.1.1.1'), ("requested_addr",cip), "end"])

		elif self.send_different_option == 'dns':
	       		L6 = DHCP(options=[("message-type","request"),("server_id",server_id),
        	                   	("subnet_mask",subnet_mask), ("name_server",'1.1.1.1'), ("requested_addr",cip), "end"])

	elif lease_time:
             L6 = DHCP(options=[("message-type","request"), ("server_id",server_id),
                                ("subnet_mask",subnet_mask), ("requested_addr",cip),("lease_time",lease_value), "end"])
	else:
             L6 = DHCP(options=[("message-type","request"), ("server_id",server_id),
                           	("subnet_mask",subnet_mask), ("requested_addr",cip), "end"])

	resp=srp1(L2/L3/L4/L5/L6, filter="udp and port 68", timeout=10, iface=self.iface)
	#log_test.info('request packet is %s'%(L2/L3/L4/L5/L6).show())
	#log_test.info('response packet is %s'%resp.show())
	if resp == None:
        	return (None, None)


	self.servermac = resp.getlayer(Ether).src

	for x in resp.lastlayer().options:
            	if(x == 'end'):
                	break
            	op,val = x
            	if(op == "message-type"):

			if(val == 5):
				try:
            				srcIP = resp.yiaddr
            				serverIP = resp.siaddr
					self.mac_map[mac] = (srcIP, serverIP)
                                        self.mac_inverse_map[srcIP] = (mac, serverIP)
        			except AttributeError:
           				log_test.info("In Attribute error.")
            				log_test.info("Failed to acquire IP via DHCP for %s on interface %s" %(mac, self.iface))
            				return (None, None)

				if lease_time or renew_time or rebind_time or self.specific_lease:
					for x in resp.lastlayer().options:
            					if(x == 'end'):
                					break
	            				op,val = x

        	    				if op == "lease_time":

							if self.specific_lease:
								return (srcIP, serverIP, val)
							if lease_time == True:
								self.mac_map[mac] = (srcIP, serverIP)
			        				self.mac_inverse_map[srcIP] = (mac, serverIP)
								return (srcIP, serverIP, val)
	            				elif op == "renewal_time":
							if renew_time == True:
								self.mac_map[mac] = (srcIP, serverIP)
				        			self.mac_inverse_map[srcIP] = (mac, serverIP)
								return (srcIP, serverIP, val)
            					elif op == "rebinding_time":
							if rebind_time == True:
								self.mac_map[mac] = (srcIP, serverIP)
			        				self.mac_inverse_map[srcIP] = (mac, serverIP)
								return (srcIP, serverIP, val)
				else:
					self.mac_map[mac] = (srcIP, serverIP)
					self.mac_inverse_map[srcIP] = (mac, serverIP)
					return (srcIP, serverIP)
			elif(val == 6):

				log_test.info("Got DHCP NAK.")
				return (None, None)



    def discover_next(self):
        '''Send next dhcp discover/request with updated mac'''
        return self.discover(update_seed = True)

    def release(self, ip):
        '''Send a DHCP discover/offer'''
        if ip is None:
            return False
        if not self.mac_inverse_map.has_key(ip):
            return False
        mac, server_ip = self.mac_inverse_map[ip]
        chmac = self.macToChaddr(mac)
        L2 = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
        L3 = IP(src="0.0.0.0", dst="255.255.255.255")
        L4 = UDP(sport=68, dport=67)
        L5 = BOOTP(chaddr=chmac, ciaddr = ip)
        L6 = DHCP(options=[("message-type","release"), ("server_id", server_ip), "end"])
        sendp(L2/L3/L4/L5/L6, iface = self.iface, count=2)
	#log_test.info('release response is %s'%resp)
        del self.mac_map[mac]
        del self.mac_inverse_map[ip]
        return True

    def macToChaddr(self, mac):
        rv = []
        mac = mac.split(":")
        for x in mac:
            rv.append(chr(int(x, 16)))
        return reduce(lambda x,y: x + y, rv)

    def get_ip(self, mac):
        if self.mac_map.has_key(mac):
            return self.mac_map[mac]
        return (None, None)

    def get_mac(self, ip):
        if self.mac_inverse_map.has_key(ip):
            return self.mac_inverse_map[ip]
        return (None, None)

    def ipToMac(self, ip):
        '''Generate a mac from a ip'''

        mcast = self.is_mcast(ip)
        mac = "01:00:5e" if mcast == True else "00:00:00"
        octets = ip.split(".")
        for x in range(1,4):
            num = str(hex(int(octets[x])))
            num =  num.split("x")[1]
            if len(num) < 2:
                num = "0" + str(num)
            mac += ":" + num
        return mac

    def incIP(self, ip, n=1):
        '''Increment an IP'''

        if n < 1:
            return ip
        o = ip.split(".")
        for ii in range(3,-1,-1):
            if int(o[ii]) < 255:
                o[ii] = str(int(o[ii]) + 1)
                break
            else:
                o[ii] = str(0)

        n -= 1
        return self.incIP(".".join(o), n)
