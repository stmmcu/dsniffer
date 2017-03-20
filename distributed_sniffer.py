import json
import requests
import re
import time
import argparse

from n7k_span import *
from ndb import *
from epc import *
from start_capture import *
from pcap3 import *

n7k_sw = ['172.16.118.154']
span_dest_intf = {'172.16.118.154':'eth7/11'}
span_sess_num = 48

routers = ['172.16.119.2','172.16.119.4','172.16.49.1']
capture_intf = ['gig0/1/7','gig0/2/0','gig0/0/0']

sniffer_hosts=[{
  'ip':'172.16.118.89',
  'name':'Wireshark',
  'user':'xxxx',
  'pwd':'yyyy',
  'capture_intf':'ens34',
  'file_name':'host1.pcap'
}]

files = ['host1.pcap','router1.pcap','router2.pcap','router3.pcap']

parser = argparse.ArgumentParser(description='Input src and dst IP address')
parser.add_argument('--src', dest='src_ip',help='source IP') 
parser.add_argument('--dst', dest='dst_ip',help='destination IP')
args = parser.parse_args()
src_ip = args.src_ip
dst_ip = args.dst_ip
print(args.src_ip)
print(args.dst_ip)

span_main(n7k_sw,src_ip,dst_ip,span_dest_intf,span_sess_num)
ndb_main(src_ip,dst_ip)
epc_main(routers,capture_intf,src_ip,dst_ip)
capture_main(sniffer_hosts,routers,files,src_ip,dst_ip)
pcap_main(files,src_ip,dst_ip)
