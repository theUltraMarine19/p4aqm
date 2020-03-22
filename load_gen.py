import sys
from scapy.all import *
from random import randint
import time

dst_ip = sys.argv[1]

def send_pkt(n):
    send(IP(dst=dst_ip)/UDP()/Input_pkt(), count=n)  # Layer 3 pkts (tos = 0 => ecn = 0)

def main():
  num_pkts = 1000
  send_pkt(1000)
  
if __name__ == '__main__':
  main()
