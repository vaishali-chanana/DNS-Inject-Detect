import argparse
import os
from scapy.all import *
import datetime
packet_dict={}

def check_arg():
	parser = argparse.ArgumentParser(description='DNS Inject', add_help=False)
	parser.add_argument('-i', nargs='?', action="store")
	parser.add_argument('-r', nargs='?', action="store")
	parser.add_argument('expression', nargs='*',action="store")
	args = parser.parse_args()

	return args.i, args.r, args.expression

def dns_detect(packet):
	if(packet.haslayer(DNSRR)):
		#packet.show()
		list1=[]
		for i in range(packet[DNS].ancount):
			list1.append(packet[DNS].an[i].rdata)

		src1 = packet.src
		ttl1 = packet[IP].ttl

		if(packet[DNS].id in packet_dict.keys()):
			rdata1 = list1
			rdata2 = packet_dict[packet[DNS].id][2]
			#src1 = packet.src
			src2 = packet_dict[packet[DNS].id][0]
			# ...............Get TTL......................
			#ttl1 = packet[IP].ttl
			ttl2 = packet_dict[packet[DNS].id][1]
			# ...............Check for no intersection ....................
			rdata = list(set(rdata1) & set(rdata2))
			if not rdata:
				if(src1!=src2 or ttl1!=ttl2):
					#print(packet.time,"DNS Detected")
					print(datetime.datetime.fromtimestamp(packet.time).strftime('%Y%m%d-%H:%M:%S'),"DNS poisoning detected")
					print("TXID", packet[DNS].id, "Request", packet[DNS].qd.qname.decode('ASCII')[:-1])
					print("Answer1", rdata2)
					print("Answer2", rdata1)
		else:
			packet_dict[packet[DNS].id] = (src1,ttl1,list1)
        
if __name__ == '__main__':
	interface,tracefile,expression = check_arg()
	print("interface",interface)
	print("tracefile", tracefile)   
	print("expression",expression)

	rFlag=0
	iFlag=0
	#packets = rdpcap(tracefile)
	if not expression:
		expression=""
	if(tracefile!=None):
		rFlag = 1
		packets = rdpcap(tracefile)
		for packet in packets:
			dns_detect(packet)      
	elif(interface!=None):
		iFlag = 1
		sniff(filter=expression, prn=dns_detect, store=0, iface=interface)
	else:
		# ........................Figure out a way to get default interface ......................
		#interface = 'ens33'
		sniff(filter=expression, prn = dns_detect, store =0)
