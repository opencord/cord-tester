#!/usr/bin/env python
##Generate a port map for 100 subscribers based on veth pairs
import sys
header = '''###This file is auto-generated. Do not EDIT###'''
def generate_port_map(num = 100):
    print("g_subscriber_port_map = {}")
    print("g_subscriber_reverse_port_map = {}")
    for i in xrange(1, num+1):
        intf = 'veth' + str(2*i-2)
        print("g_subscriber_port_map[%d]='%s'" %(i, intf))
        print("g_subscriber_reverse_port_map['%s']=%d" %(intf, i))

if __name__ == '__main__':
    num = 100
    if len(sys.argv) > 1:
        num = int(sys.argv[1])
    print(header)
    generate_port_map(num)
