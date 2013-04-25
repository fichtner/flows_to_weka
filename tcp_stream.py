from scapy.all import *
import scapy
from numpy import *
#We are assuming:
#1) Its an IP packet
#2) Its an TCP packet
class TCPStream:
	def __init__(self,pkt):
		self.src = pkt.src 
		self.dst = pkt.dst
		self.flags = [pkt.sprintf("%TCP.flags%")]
		self.sport = pkt.sport
		self.dport = pkt.dport        
		self.time = pkt.time
		self.proto = pkt.proto
		self.inter_arrival_times = [0]
		self.pkt_count = 1
		self.len = pkt.len
		self.pkt = pkt

        def unique_flags(self):
	    seen = set()
	    for item in self.flags:
	        if item not in seen:
	            seen.add( item )
		    yield item

	def avrg_len(self):
		return self.len/self.pkt_count

	def avrg_inter_arrival_time(self):
		return round(mean(self.inter_arrival_times),4)

	def push_flag_ratio(self):
		return len([ f for f in self.flags if 'P' in f ]) / float(len(self.flags))

	def add(self,pkt):
		self.pkt_count += 1
		self.len += pkt.len
		self.inter_arrival_times.append(pkt.time - self.time)
		self.flags.append(pkt.sprintf("%TCP.flags%"))
		self.pkt = pkt

	def remove(self,pkt):
		raise Exception('Not Implemented')
