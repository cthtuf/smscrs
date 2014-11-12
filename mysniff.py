#mysniff.py [packetcount [filter]]
#mysniff.py 10
#mysniff.py 20 icmp
#filter has BPF syntax

import sys
import string
from threading import Thread

from pcapy import findalldevs, open_live
from impacket.ImpactPacket import Ethernet,IP,TCP,UDP,ICMP,ARP

def num_from_barray(p_barr):
	sum = 0
	idx = 0
	p_barr.reverse()
	while idx < len(p_barr):
		sum+=int(p_barr[idx])*2**idx
		idx+=1
	return sum

class DecoderThread(Thread):
	def __init__(self, pcapObj, p_lim):
		self.lim = p_lim
		print "packet count limited by %d" % self.lim
		self.pcap = pcapObj
		Thread.__init__(self)

	def run(self):
		self.pcap.loop(self.lim, self.packetHandler)

	def packetHandler(self, hdr, data):
		e = Ethernet(data)
		eoff = e.get_header_size()
		print "==============================================================="
		print "Eth:\n\thdrsize:%s\n\tsourceaddr:%s\n\tdestaddr:%s\n\tethtype:%s" % (eoff, num_from_barray(e.get_ether_shost()), num_from_barray(e.get_ether_dhost()), e.get_ether_type())
		if e.get_ether_type() == IP.ethertype:
			ipdata = data[eoff:]
			i = IP(ipdata)
			ioff = i.get_header_size()
			print "\tproto:IP\n\t\tipversion:%s\n\t\thdrsize:%s\n\t\ttos:%s\n\t\tipsize:%s\n\t\tid:%s\n\t\tdf:%s\n\t\tmf:%s\n\t\toffset:%s\n\t\tttl:%s\n\t\tproto:%s\n\t\tsum:%s\n\t\tsrc:%s\n\t\tdst:%s" % (i.get_ip_v(), i.get_header_size(), i.get_ip_tos(), i.get_ip_len(), i.get_ip_id(), i.get_ip_df(), i.get_ip_mf(), i.get_ip_off(), i.get_ip_ttl(), i.get_ip_p(), i.get_ip_sum(), num_from_barray(i.get_ip_src().split('.')), num_from_barray(i.get_ip_dst().split('.')))
			if i.get_ip_p() == UDP.protocol:
				udpdata = ipdata[ioff:]
				u = UDP(udpdata)
				print "\t\tproto:UDP\n\t\t\tsrcport:%s\n\t\t\tdstport:%s\n\t\t\tsize:%s\n\t\t\tcksum:%s" % (u.get_uh_sport(), u.get_uh_dport(), u.get_uh_ulen(), u.get_uh_sum())
			elif i.get_ip_p() == TCP.protocol:
				tcpdata = ipdata[ioff:]
				t = TCP(tcpdata)
				print "\t\tproto:TCP\n\t\t\tsrcport:%s\n\t\t\tdstport:%s\n\t\t\tseq:%s\n\t\t\tack:%s\n\t\t\tflags:%s\n\t\t\twinsize:%s\n\t\t\tcksum:%s\n\t\t\turg:%s\n\t\t\topts:%s" % (t.get_th_sport(), t.get_th_dport(), t.get_th_seq(), t.get_th_ack(), t.get_th_flags(), t.get_th_win(), t.get_th_sum(), t.get_URG(), '0')#t.get_options()
			elif i.get_ip_p() == ICMP.protocol:
				icmpdata = ipdata[ioff:]
				ic = ICMP(icmpdata)
				print "\t\tproto:ICMP\n\t\t\ttype:%s\n\t\t\tcode:%s\n\t\t\tcksum:%s\n\t\t\tid:%s\n\t\t\tseq:%s\n\t\t\tgwaddr:%s\n\t\t\tmask:%s" % (ic.get_icmp_type(), ic.get_icmp_code(), ic.get_icmp_cksum(), ic.get_icmp_id(), ic.get_icmp_seq(), ic.get_icmp_gwaddr(), ic.get_icmp_mask())
			else:
				print "\t\tunknown child protocol"
		elif e.get_ether_type() == ARP.ethertype:
			adata = data[eoff:]
			a = ARP(adata)
			print "\tproto:ARP\n\t\thrd:%s\n\t\tpro:%s\n\t\thlen:%s\n\t\tplen:%s\n\t\top:%s\n\t\tsha:%s\n\t\tspa:%s\n\t\ttha:%s\n\t\ttpa:%s" % (a.get_ar_hrd(), a.get_ar_pro(), a.get_ar_hln(), a.get_ar_pln(), a.get_ar_op(), num_from_barray(a.get_ar_sha()), num_from_barray(a.get_ar_spa()), num_from_barray(a.get_ar_tha()), num_from_barray(a.get_ar_tpa()))
		else:
			print "\tunknown child protocol"		
		print "==============================================================="


def getInterface():
	ifs = findalldevs()
	if 0 == len(ifs):
		print "You don't have enough permissions to open any interface on this system."
		sys.exit(1)
	elif 1 == len(ifs):
		print 'Only one interface present, defaulting to it.'
	return ifs[0]
	count = 0
	for iface in ifs:
		print '%i - %s' % (count, iface)
	count += 1
	idx = int(raw_input('Please select an interface: '))
	return ifs[idx]

def main(filter, p_lim):
	dev = getInterface()
	p = open_live(dev, 1500, 0, 100)
	p.setfilter(filter)

	print "Listening on %s: net=%s, mask=%s, linktype=%d" % (dev, p.getnet(), p.getmask(), p.datalink())

	DecoderThread(p, p_lim).start()

filter = ''
if len(sys.argv) > 1:
	lim = int(sys.argv[1])
else:
	lim = 10
if len(sys.argv) > 2:
	filter = ' '.join(sys.argv[2:])
main(filter, lim)
