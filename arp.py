#!/usr/bin/env/python3

import socket
import struct

class Ethernet(object):

	def __init__(self):
		self.dst = None
		self.src = None
		self.etype = None


class Arp(object):

	def __init__(self):
		self.htype = None
		self.ptype = None
		self.hsize = None
		self.psize = None
		self.op = None
		self.shwa = None
		self.spa = None
		self.thwa = None
		self.tpa = None
		self.padd = None

eth = Ethernet()
eth.dst = b'\xff\xff\xff\xff\xff\xff'
eth.src = b'\xe0\x9d\x31\x2e\xfe\x3c'
eth.etype = 0x0806

arp = Arp()
arp.htype = 0x01 #2 bytes
arp.ptype =0x0800 #2 bytes
arp.hsize = 0x06  #1 byte
arp.psize = 0x04  #1 byte
arp.op = 0x01  #2 bytes
arp.shwa = b'\xe0\x9d\x31\x2e\xfe\x3c'
arp.spa = socket.inet_aton('192.168.0.56')
arp.thwa = b'\x00\x00\x00\x00\x00\x00'
arp.tpa = socket.inet_aton('192.168.0.38')
arp.padd = b'\x49\x20\x6c\x6f\x76\x65\x20\x6e\x65\x74\x77\x6f\x72\x6b\x69\x6e\x67\x21'


frame = struct.pack('!6s6sH',eth.dst,eth.src,eth.etype)

arpf = struct.pack('!HHBBH6s4s6s4s18s',arp.htype,arp.ptype,arp.hsize,arp.psize,arp.op,arp.shwa,arp.spa,arp.thwa,arp.tpa,arp.padd)

packet = frame+arpf

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,socket.htons(0x800))
s.bind(('wlan0',0))

s.send(packet)





