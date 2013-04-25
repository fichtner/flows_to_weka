#!/usr/bin/env python
import sys
import hashlib
from hashlib import md5
from scapy.all import *
from tcp_stream import TCPStream
import argparse


#to test:
#add for every tcp flag a counter. accumulate it per flow
#do a chi square test to see if the number of flags are related with a protocol
#ex:
#http://hsc.uwe.ac.uk/dataanalysis/quantinfasschi.asp
#packets=rdpcap("tcp_or_udp.pcap")


def create_forward_flow_key(pkt):
	return "%s:%s->%s:%s:%s"%(pkt.src,pkt.sport,pkt.dst,pkt.dport,pkt.proto)
def create_reverse_flow_key(pkt):
	return "%s:%s->%s:%s:%s"%(pkt.dst,pkt.dport,pkt.src,pkt.sport,pkt.proto)
def create_flow_keys(pkt):
	return create_forward_flow_key(pkt),create_reverse_flow_key(pkt)

def lookup_stream(key,reverse_key):

	if key in flows.keys():
		return key,flows[key]
	elif reverse_key in flows.keys():
		return reverse_key,flows[reverse_key]
	else: 
		return key,None


#I'm just using here, because I know my trace. Normally this function shouldn't use sport and dport. Instead a DPI engine 
#HINT: appid https://code.google.com/p/appid/
def port_to_name(sport,dport):
	if dport == 80 or sport == 80:
		return "http"
	if dport == 3306 or sport == 3306:
		return "mysql" 
	if dport == 22 or sport == 22:
		return "ssh"
	return "unknown"

parser = argparse.ArgumentParser(description='Process a pcap file, generating the flows and output it as arff or csv')
parser.add_argument('-i',help="pcap file to be readin",required=True)
parser.add_argument('-o',help="output file to be written")
parser.add_argument('-t',help="type of output arff or csv",default='arff',choices=['arff','csv'])
args = parser.parse_args()


pcap_file = vars(args)['i']
output_type = vars(args)['t']

packets=rdpcap(pcap_file)

flows = {}

attrs = ['src','sport','dst','dport','proto','push_flag_ratio','average_len','pkt_count','flow_average_inter_arrival_time']
#reduce it to TCP
#TODO check if its possible to pack it again in the original class, that we are able to call .conversations() on this array
packets = [ pkt for pkt in packets if IP in pkt for p in pkt if TCP in p ]

#here we are sure ALL PACKETS ARE TCP
for pkt in packets:
	 flow_tuple = reverse_flow_tuple = key_to_search = None
	 flow_tuple,reverse_flow_tuple = create_flow_keys(pkt[IP])
	 flow_key,tcp_stream = lookup_stream(flow_tuple,reverse_flow_tuple)

	 if tcp_stream is None:
	   tcp_stream = TCPStream(pkt[IP])
	 else:
	   tcp_stream.add(pkt[IP])

	 flows[flow_key] = tcp_stream

if output_type == "arff":
	print "@relation protocol_detection"
	print "@attribute protocol-name","{ssh,http,mysql,unknown}"

	for attr in attrs:
		if attr in ['pkt_count','average_len','flow_average_inter_arrival_time','push_flag_ratio']:
			print "@attribute",attr,"numeric"
		else:
			print "@attribute",attr,"string"
	print "@data"
else:
	attrs.insert(0,"protocol_name")
	print ','.join(attrs)

for flow in flows.values():
	print "%s,%s,%s,%s,%s,%s,%.3f,%s,%s,%s"%(port_to_name(flow.dport,flow.sport),flow.src,flow.sport,flow.dst,flow.dport,flow.proto,flow.push_flag_ratio(),flow.avrg_len(),flow.pkt_count,flow.avrg_inter_arrival_time())
