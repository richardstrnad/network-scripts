import struct
import socket

#Author - Grzegorz Wypych (horac)

##Example how to dissect OSPF packet and calculate checksum"

#Raw ospf packet sniffed on interface

pktOSPF = "\x02\x01\x00,\xc0\xa8\x00*\x00\x00\x00\x00j\xf9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\x00\x00\n\x12\x01\x00\x00\x00(\xc0\xa8\x00*\x00\x00\x00\x00\xff\xf6\x00\x03\x00\x01\x00\x04\x00\x00\x00\x01"


#Function that gets  OSPF header details from OSPF packet

def dissectOSPFheader(pktOSPF):
    OSPFheader = pktOSPF[:24]
    OSPFheader = struct.unpack("!BBH4s4sHH4s4s",OSPFheader)
    OSPFheader = list(OSPFheader)
    #print OSPFheader
    print "---------OSPF header---------"
    print " "
    print "Version:",OSPFheader[0]
    print "Type:",OSPFheader[1]
    print "Length:",OSPFheader[2]
    print "Router ID:",socket.inet_ntoa(OSPFheader[3])
    print "Area ID:",socket.inet_ntoa(OSPFheader[4])
    print "Checksum:",hex(OSPFheader[5])
    print "AuType:",OSPFheader[6]
    print "Authentication field 1:", socket.inet_ntoa(OSPFheader[7])
    print "Authentication field 2:", socket.inet_ntoa(OSPFheader[8])
    print " "

#Function that gets OSPF hell from OSPF packet

def dissectOSPFhello(pktOSPF):
   OSPFhello = pktOSPF[24:44]
   OSPFhello = struct.unpack("!4sHBB4s4s4s",OSPFhello)
   OSPFhello = list(OSPFhello)
   #print OSPFhello
   print "---------OSPF hello packet---------"
   print " "
   print "Network mask:", socket.inet_ntoa(OSPFhello[0])
   print "Hello interval:",OSPFhello[1]
   print "Option:", hex(OSPFhello[2])
   print "Router priority:", OSPFhello[3]
   print "Router dead interval:", list(struct.unpack("!L",OSPFhello[4]))[0]
   print "Designated router:",socket.inet_ntoa(OSPFhello[5])
   print "Backup designated router",socket.inet_ntoa(OSPFhello[5])
   print "Active Neighbors:", socket.inet_ntoa(OSPFhello[6])

#checksum calculation for OSPF packet, should be the same as OSPF header checksum field

def calcChecksum(pktOSPF):
    pktOSPF = pktOSPF[:56]
    fields = struct.unpack("!28H",pktOSPF)
    fields = list(fields)
    print "--------OSPF Checksum calulcation---------"
    print "  "
    print "All OSPF hello header fields (header OSPF + hello OSPF):",[hex(f) for f in fields]
    sum = 0
    print "First zeroize current checksum and auth fields for calculation: "
    fields[6] = 0
    fields[8] = 0
    fields[9] = 0
    print "Next add all remains field and convert to hex"
    for f in fields:
        sum += f
    sum = hex(sum)
    print "Sum of OSPF packet field in hex:",sum
    compl = "0x"+sum[-4:]
    carry = sum[:len(sum)-4]
    print "last 4 bytes of sum:",compl
    print "Carry is:",carry
    compl = int(compl,16) + int(carry,16)
    print "Sum of carry and last 4 bytes:",hex(compl)
    checksum = compl ^ 0xffff
    print "Correct checksum of OSPF header  after bit flipping:",hex(checksum)
    return hex(checksum)

dissectOSPFheader(pktOSPF)
dissectOSPFhello(pktOSPF)
calcChecksum(pktOSPF)




