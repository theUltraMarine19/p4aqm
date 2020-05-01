from scapy.all import *

pkts = rdpcap('s1-eth2_in.pcap')

for pkt in pkts:
	if (pkt.haslayer(Dot1Q)):
		print pkt.getlayer(Dot1Q).vlan
