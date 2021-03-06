#!/usr/bin/python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink, Link
from mininet.node import OVSController

from p4_mininet import P4Switch, P4Host
# from p4utils.utils.sswitch_API import *

import os
import json
import argparse
import subprocess
from time import sleep
from collections import OrderedDict

_THIS_DIR = os.path.dirname(os.path.realpath(__file__))
_THRIFT_BASE_PORT = 9091

parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
					type=str, action="store", required=True)
parser.add_argument('--json', help='Path to JSON config file',
					type=str, action="store", required=True)
parser.add_argument('--cli', help='Path to BM CLI',
					type=str, action="store", required=True)

args = parser.parse_args()

class MyTopo(Topo):
	def __init__(self, sw_path, json_path, nb_hosts, nb_switches, links, **opts):
		# Initialize topology and default options
		Topo.__init__(self, **opts)
		
		# json burnt here. No need for p4runtime
		for i in xrange(nb_switches):
			switch = self.addSwitch('s%d' % (i + 1),		# first arg is name of the switch
									cls = P4Switch,
									sw_path = sw_path,
									json_path = json_path+".json", # Change!
									thrift_port = _THRIFT_BASE_PORT + i,
									pcap_dump = True,
									device_id = i,
									log_console = True,
									verbose = True)

		for h in xrange(nb_hosts):
			host = self.addHost('h%d' % (h + 1))

		ctr = 1
		for a, b in links:
			if a == "h2" and b == "s1":
				# print "Slowing down h2-s1 link"
				self.addLink(a, b, 1, ctr, bw=1000)
				self.addLink(a, b, 2, ctr+nb_hosts, intfName1='eth1', bw=1000)
			else:
				self.addLink(a, b, 1, ctr, bw=1000, delay='1000us', loss=0)
				self.addLink(a, b, 2, ctr+nb_hosts, intfName1='eth1', bw=1000, delay='0ms', loss=0)
			# if a.startswith("h"):
			# 	self.addLink(a, b, 2, ctr+nb_hosts, intfName1='eth1', bw=10)

			ctr += 1

def get_links(json_links):
    links = []
    for key in json_links:
        link = json_links[key]
        a, b = link["_0"], link["_1"]  
        links.append( (a, b) )
    return links

def main():

	topo_data = None
	with open('topology/topo.json','r') as f:
		topo_data = json.load(f, object_pairs_hook=OrderedDict)

	nb_hosts = topo_data["nb_hosts"]
	nb_switches = topo_data["nb_switches"]

	topo = MyTopo(args.behavioral_exe,
				  args.json,
				  nb_hosts, 
				  nb_switches, 
				  get_links(topo_data["links"]))

	net = Mininet(topo = topo,
				  host = P4Host,
				  switch = P4Switch,
				  link = TCLink,
				  controller = None)
	net.start()

	for n in xrange(nb_hosts):
		h = net.get('h%d' % (n + 1))
		for off in ["rx", "tx", "sg"]:
			cmd = "/sbin/ethtool --offload eth0 %s off" % off # disable rx/tx/sg checksum offloading at the hosts
			print cmd
			h.cmd(cmd)
		print "disable ipv6"
		h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
		h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
		h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
		h.cmd("sysctl -w net.ipv4.tcp_congestion_control=reno") # This is default TCP congestion control mechanism

		h.cmd('ifconfig eth1 10.0.1.' + str(n+1) + ' netmask 255.255.255.0')
		#h.cmd("iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP") # drop ICMP packets saying "Host unreachable"

	sleep(1)

	for i in xrange(nb_switches):
		cmd = [args.cli, "--json", args.json + ".json" , # Change! Removed str(i+1) from here 
			   "--thrift-port", str(_THRIFT_BASE_PORT + i)] #, "--log-file", "switch"+str(i+1) +".log", "--log-flush"]
		
		# push all the same rules for 3 switches to runtime_CLI here
		with open("./cli_commands/rules_original.txt", "r") as f:
			# print " ".join(cmd)
			try:
				output = subprocess.check_output(cmd, stdin = f)
				# print output
			except subprocess.CalledProcessError as e:
				print e
				print e.output



	sleep(1)

	print "Ready !"

	CLI( net )
	net.stop()

if __name__ == '__main__':
	setLogLevel( 'info' )
	main()
