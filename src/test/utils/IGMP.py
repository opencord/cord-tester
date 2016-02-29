from socket import *
from struct import *
from scapy.all import *
from itertools import *

IGMPV3_REPORT = 0x22
IGMP_LEAVE = 0x17
IGMP_EXCLUDE = 0x04
IGMP_INCLUDE = 0x03
IGMPV3_ALL_ROUTERS = '224.0.0.22'
IGMPv3 = 3
IP_SRC = '1.2.3.4'
ETHERTYPE_IP = 0x0800
IGMP_DST_MAC = "01:00:5e:00:01:01"
IGMP_SRC_MAC = "5a:e1:ac:ec:4d:a1"

class IGMP:

    def __init__(self, mtype = None, group = '', rtype = None, src_list = []):
        self.version = IGMPv3
        self.mtype = mtype
        self.group = group
        self.src_list= src_list
        self.rtype = rtype

    def checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = ord(msg[i]) + (ord(msg[i+1]) << 8)
            c = s + w
            s = (c & 0xffff) + (c >> 16)
        return ~s & 0xffff

    def update_igmp_checksum(self, pkt):
        cs = self.checksum(pkt)
        #print 'igmp checksum: ' + str(hex(cs))
        m = []
        for x in pkt:        
            m.append(ord(x))
        higher = (cs >> 8) & 0xff
        lower = cs & 0xff
        m[2] = lower
        m[3] = higher
        m = pack("%dB" % len(m), *m)
        return m

    def update_ip_checksum(self, pkt):
        cs = self.checksum(pkt)
        #print 'ip hdr checksum: ' + str(hex(cs))
        m = []
        for x in pkt:        
            m.append(ord(x))
        higher = (cs >> 8) & 0xff
        lower = cs & 0xff
        m[10] = lower
        m[11] = higher
        m = pack("%dB" % len(m), *m)
        return m

    def build_ip_hdr(self, s, d):
        ip_ihl_len = 0x46 #8 bits
        ip_dscp = 0xc0 #8 bits
        ip_hdr_total_len = 0x0028 #16 bits
        ip_id = 0x0000 #16 bits
        ip_flags = 0x4000 #16 bits
        ip_ttl = 1 #8 bits
        ip_protocol = 0x02 #8 bits
        ip_cs = 0x0000 #16 bits (should filled by kernel but seems not???)
        #ip_src #32 bits
        #ip_dst #32 bits
        ip_options = 0x94040000 #32 bits
        #total len 24 bytes
        ip_header = pack('!BBHHHBBH4s4sI', ip_ihl_len, ip_dscp, ip_hdr_total_len,
                         ip_id, ip_flags, ip_ttl, ip_protocol, ip_cs, inet_aton(s),
                         inet_aton(d), ip_options)
        return ip_header

    def dump_packet(self, data):
        i = 0
        for x in data:
            if i == 4:
                print ''
                i = 0
            i += 1
            sys.stdout.write(' %0.2x' % ord(x))
        print ''

    def build_igmp(self, msg_type = None, group = None, record_type = None, src_list = None):
        msg_type = self.mtype if msg_type == None else msg_type
        group = self.group if group == None else group
        record_type = self.rtype if record_type == None else record_type
        src_list = self.src_list if src_list == None else src_list
        if msg_type == IGMP_LEAVE:
            pkt = pack('!BBH4s', msg_type, 0, 0, inet_aton(group))
        elif msg_type == IGMPV3_REPORT:
            pkt = pack('!BBHHHBBH', msg_type, 0x00, 0x0000, 0x0000, 0x0001, record_type,
                       0x00, len(src_list))
            pkt += pack('!4s', inet_aton(group))
            for a in src_list:
                pkt += pack('!4s', inet_aton(a))
        else:
            print 'unsupported report type: ' + str(msg_type)
            return None
        return pkt

    def build_join_msg(self, group = None, record_type = None, src_list = None):
        return self.build_igmp(msg_type = IGMPV3_REPORT, 
                               group = group, 
                               record_type = record_type, 
                               src_list = src_list)

    def build_leave_msg(self, group = None):
        return self.build_igmp(msg_type = IGMPV3_REPORT, 
                               group = group, 
                               record_type = IGMP_INCLUDE, 
                               src_list = [])

    def build_ip_igmp(self, 
                      src = IP_SRC,
                      msg_type = None, 
                      group = None, 
                      record_type = None, 
                      src_list = None):

        igmp = self.build_igmp(msg_type = msg_type,
                               group = group,
                               record_type = record_type,
                               src_list = src_list)
        igmp = self.update_igmp_checksum(igmp)
        ip_hdr = self.build_ip_hdr(src, IGMPV3_ALL_ROUTERS)
        p = ip_hdr + igmp
        p = self.update_ip_checksum(p)
        return p

    def scapify(self, 
                src = IP_SRC, 
                msg_type = None,
                group = None,
                record_type = None,
                src_list = None):

        ip_igmp = self.build_ip_igmp(src = src,
                                     msg_type = msg_type,
                                     group = group,
                                     record_type = record_type,
                                     src_list = src_list)
        eth = Ether(dst = IGMP_DST_MAC, src = IGMP_SRC_MAC, type = ETHERTYPE_IP)
        return eth/ip_igmp
