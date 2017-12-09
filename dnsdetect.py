import argparse
import os
from scapy.all import *
packet_dict={}

def check_arg():
	parser = argparse.ArgumentParser(description='DNS Inject', add_help=False)
	parser.add_argument('-i', nargs='?', action="store")
	parser.add_argument('-r', nargs='?', action="store")
	parser.add_argument('expression', nargs='*',action="store")
	args = parser.parse_args()

	return args.i, args.r, args.expression

def dns_detect(packet):
	#packet.show()
	if(packet.haslayer(DNSRR)):
		list1=[]
		for i in range(packet[DNS].ancount):
			print("type",packet[DNS].an[i].type)
			#if(packet[DNS].an[i].type=="A"):
			print("rdata", packet[DNS].an[i].rdata)
			list1.append(packet[DNS].an[i].rdata)
		if(packet[DNS].id in packet_dict.keys()):
			# .............. Make list for both ............................
			rdata1 = list1
			rdata2 = packet_dict[packet[DNS].id]
			print(rdata1)
			print(rdata2)
			# ...............Check for no intersection ....................
			if(rdata1!=rdata2):
				print("TXID", packet[DNS].id, "Request", packet[DNS].qd.qname.decode('ASCII')[:-1])
				print("Answer1", rdata2)
				print("Answer2", rdata1)
		else:
			packet_dict[packet[DNS].id] = list1
			print(packet_dict)
        
if __name__ == '__main__':
	interface,tracefile,expression = check_arg()
	print("interface",interface)
	print("tracefile", tracefile)   
	print("expression",expression)

	rFlag=0
	iFlag=0
	packets = rdpcap(tracefile)
	if(tracefile!=None):
		rFlag = 1
		packets = rdpcap(tracefile)
		for packet in packets:
			dns_detect(packet)      
	elif(interface!=None):
		iFlag = 1
		sniff(filter="udp port 53", prn=dns_detect, store=0, iface=interface)
	else:
		# ........................Figure out a way to get default interface ......................
		interface = 'ens33'
		sniff(filter="udp port 53", prn = dns_detect, store =0, iface=interface)
