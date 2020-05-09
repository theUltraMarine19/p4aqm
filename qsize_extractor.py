import sys
from scapy.all import *

pkts = rdpcap('s1-eth2_in.pcap')
maxm = 0
cnt = 0
start = {}
end = {}
t0 = 0.0
ctr = {}

for pkt in pkts:
	# if (UDP(pkt) and IP(pkt)):
		if cnt == 0:
			t0 = pkt.time
		cnt += 1
		pkt_time = pkt.time - t0 # in secs
		if pkt.getlayer(UDP).sport not in start:
			start[pkt.getlayer(UDP).sport] = pkt_time
		end[pkt.getlayer(UDP).sport] = pkt_time
		if pkt.getlayer(UDP).sport not in ctr:
			ctr[pkt.getlayer(UDP).sport] = 0
		ctr[pkt.getlayer(UDP).sport] += 1
		val = pkt.getlayer(UDP).chksum
		# print val, pkt.getlayer(UDP).sport
		print val
		if (maxm < val):
			maxm = val

print >> sys.stderr, maxm, cnt
for key in start:
	print >> sys.stderr, key, ctr[key], end[key]-start[key]
