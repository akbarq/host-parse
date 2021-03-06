#Author : Akbar Qureshi
#Extracts number of unique hosts by connection count.

import dpkt
import sys
from socket import inet_ntoa as to_ip
import datetime
from collections import Counter

if len(sys.argv) < 2:
    sys.exit('Usage: %s pcap-file' % sys.argv[0])

pcap_file = open(sys.argv[1], "r")
pcap = dpkt.pcap.Reader(pcap_file)

hosts = []
for timestamp, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    if tcp.__class__.__name__ == 'TCP':
        if tcp.dport == 80 and len(tcp.data) > 0:
            try:
                http = dpkt.http.Request(tcp.data)
                hosts.append(http.headers['host'])
            except Exception as e:
                print "Error:" % str(e)

pcap_file.close()

c = Counter(hosts).most_common()
for host,hits in c:
        print "\033[1;37;40m Host: %s  Hits: %s\033[0;37;40m" % (host,hits)

