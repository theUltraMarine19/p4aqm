import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from random import randint
import time

dst_ip = sys.argv[1]

def send_pkt(n):
    send(IP(dst=dst_ip, tos=1)/UDP(), count=n)  # Layer 3 pkts (tos = 0 => ecn = 0)

def main():
  num_pkts = int(sys.argv[2])
  send_pkt(num_pkts)
  
if __name__ == '__main__':
  main()
