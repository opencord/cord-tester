from scapy.all import *

conf.verb = 0 # Disable Scapy verbosity
conf.checkIPaddr = 0 # Don't check response packets for matching destination IPs

class DHCPTest:

    def __init__(self, seed_ip = '192.168.1.1', iface = 'veth0'):
        self.seed_ip = seed_ip
        self.seed_mac = self.ipToMac(self.seed_ip)
        self.iface = iface
        self.mac_map = {}
        self.mac_inverse_map = {}

    def is_mcast(self, ip):
        mcast_octet = (atol(ip) >> 24) & 0xff
        return True if mcast_octet >= 224 and mcast_octet <= 239 else False

    def send(self, mac = None, update_seed = False):
        '''Send a DHCP discover/offer'''

        if mac is None:
            mac = self.seed_mac
            if update_seed:
                self.seed_ip = self.incIP(self.seed_ip)
                self.seed_mac = self.ipToMac(self.seed_ip)
                mac = self.seed_mac
                
        chmac = self.macToChaddr(mac)
        L2 = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
        L3 = IP(src="0.0.0.0", dst="255.255.255.255")
        L4 = UDP(sport=68, dport=67)
        L5 = BOOTP(chaddr=chmac)
        L6 = DHCP(options=[("message-type","discover"),"end"])
        resp = srp1(L2/L3/L4/L5/L6, filter="udp and port 68", timeout=5, iface=self.iface)
        try:
            srcIP = resp.yiaddr
            serverIP = resp.siaddr
        except AttributeError:
            print("Failed to acquire IP via DHCP for %s on interface %s" %(mac, self.iface))
            return (None, None)

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
        srp1(L2/L3/L4/L5/L6, filter="udp and port 68", timeout=5, iface=self.iface)
        self.mac_map[mac] = (srcIP, serverIP)
        self.mac_inverse_map[srcIP] = (mac, serverIP)
        return (srcIP, serverIP)

    def send_next(self):
        '''Send next dhcp discover/request with updated mac'''

        return self.send(update_seed = True)

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
