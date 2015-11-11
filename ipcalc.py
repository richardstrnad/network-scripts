#!/usr/bin/python
import optparse

#########################################
# Author: Grzegorz Wypych v1.0
# compatible with Python3 and Python2.7
#########################################


class NetworkCalculator(object):

	'''class defines basic validation for ip address and mask, and it also
	base class for inheritance'''

	def __init__(self):
		self.ip_address = ''
		self.net_mask = ''
	def find_subnet(self):
		pass

	def display_subnet(self):
		pass

	def validate_ip(self,ip_address):
		valid_ips = [x for x in range(0,256)]
		ip_address = self.ip_address
		ip = []
		try:
			for i in range(0,len(ip_address)):
				ip_address[i] = int(ip_address[i])
				if ip_address[i] > 255 or len(ip_address) > 4 or len(ip_address) < 4 or ip_address[i] not in valid_ips:
					return 0
				ip.append(ip_address[i])
			return ip
		except ValueError:
			return 0
			

	def validate_mask(self,mask):
		sub_masks = [0,128,192,224,240,248,252,254,255]
		mask = self.net_mask
		valid_mask = []
		try:
			for i in range(0,len(mask)):
				mask[i] = int(mask[i])
				if mask[i]  > 255 or len(mask) >4 or len(mask) <4 or mask[i] not in sub_masks:
					return 0
				if mask[i] != 255:
					if i < len(mask)-1:
						mask[i+1] = 0
				valid_mask.append(mask[i])
			return valid_mask
		except ValueError:
				return 0

class IPCalc(NetworkCalculator):
	
	'''IPcalc inherit basic methods for validation from parent class'''

	def __init__(self):
		NetworkCalculator.__init__(self)
		self.calc_net = []

	'''find_subnet finds subnet base on provided netmask
		and ip address and doing AND between'''

	def find_subnet(self,ip_address,net_mask):
		self.ip_address = ip_address.split('.')
		self.net_mask = net_mask.split('.')
		try:
			valid_ip = self.validate_ip(self.ip_address)
			valid_mask = self.validate_mask(self.net_mask)
			for i in range(0,len(valid_ip)):
				and_result = valid_ip[i] & valid_mask[i]
				self.calc_net.append(and_result)
			return self.calc_net
		except TypeError:
				print ("Check your IP or mask")
				return 0

	'''display_subnet just display calculated subnet mask'''

	def display_subnet(self,calc_net):
		calc_net = self.calc_net
		try:
			oct1, oct2, oct3, oct4 = self.calc_net
			result = '.'.join((str(oct1),str(oct2),str(oct3),str(oct4)))
			print ("Subnet:",result)
			return result
		except ValueError:
				print ("Check your ip or mask")
				return 0

	'''range_ip is a method to find range of usable ip addresses for given subnet
	by flipping bits on current netmask and counting 1 bits and power to 2-2'''

	def range_ip(self,net_mask):
		try:
			net_mask = self.validate_mask(self.net_mask)
			binary = ''
			binary_list =[]
			flipped_list = []
			for oc in net_mask:
				binary = ('{0:08b}'.format(oc))
				binary_list.append(binary)
				flip =  ''.join('1' if x == '0' else '0' for x in binary)
				flipped_list.append(flip)
			print ("Mask  bits:   ",'.'.join(binary_list))
			print ("Flipped bits: ",'.'.join(flipped_list))
			flipped_list  = '.'.join(flipped_list)
			count =  flipped_list.count('1')
			if count > 0 and count != 1:
				count = count ** 2 -2
				print ("Valid IP range:",count)
				return count
			elif count == 1:
				count = 1
				print ("Valid IP range:",count)
			else:
				count = 1
				print ("Valid IP range:",count)
				return count
		except TypeError:
				return 0

	'''find_wildcard finds wildcard mask by substracting 0xffff mask
		with current provided  mask'''
	
	def find_wildcard(self,net_mask):
		try:
			net_mask = self.validate_mask(self.net_mask)
			mask = [255,255,255,255]
			wildcard = []
			for i in range(0,len(net_mask)):
				result = mask[i] - net_mask[i]
				wildcard.append(result)
			oct1,oct2,oct3,oct4 = wildcard
			str_wildcard = '.'.join((str(oct1),str(oct2),str(oct3),str(oct4)))
			print ("Wildcard:",str_wildcard)
			return wildcard
		except TypeError:
				return 0

	'''find_first is a method that use subnet to find first valid ip
	by adding to last octect + 1'''
	
	def find_first(self,calc_net,broadcast):
		first_ip = []
		try:
			for i in range(0,len(broadcast)):
				convert = int(broadcast[i])
				first_ip.append(convert)
			oct1,oct2,oct3,oct4 = broadcast
			calc_net = self.calc_net
			oc1,oc2,oc3,oc4 = calc_net
			if int(oc4) != int(oct4):
				oc4 = oc4+1
				first_ip = '.'.join((str(oc1),str(oc2),str(oc3),str(oc4)))
				print ("First valid IP:",first_ip)
			elif int(oc4) == int(oct4):
				first_ip = '.'.join((str(oc1),str(oc2),str(oc3),str(oc4)))
				print ("First valid IP:",first_ip)
			return first_ip
		except TypeError:
			return 0

	'''find_last is a method that finds last valid ip by substracting one
	from broadcast'''

	def find_last(self,broadcast):
		last_ip = []
		result = ''
		try:
			for i in range(0,len(broadcast)):
				convert = int(broadcast[i])
				last_ip.append(convert)
			oct1,oct2,oct3,oct4 = broadcast
			oc1,oc2,oc3,oc4 = self.calc_net
			if oct4 != oc4:
				x = int(oct4)-1
				result = '.'.join((str(oct1),str(oct2),str(oct3),str(x)))
			if int(oct4) == oc4:
				result = '.'.join((str(oct1),str(oct2),str(oct3),str(oct4)))
			print ("Last valid IP:",result)
			return last_ip
		except TypeError:
			return 0

	'''find_broadcast is a method that use subnet and wildcard mask
	and make OR binary between to find broadcast ip'''

	def find_broadcast(self,sub_add,wildcard):
		try:
			broadcast = []
			for i in range(0,len(sub_add)):
				res = sub_add[i] | wildcard[i]
				broadcast.append(str(res))
			str_broadcast = '.'.join(broadcast)
			print ("Broadcast IP:",str_broadcast)
			return broadcast
		except TypeError:
			return 0

	def find_slashed_mask(self,mask):
		try:
			net_mask = self.validate_mask(self.net_mask)
			binary_list=[]
			for oc in net_mask:
				binary = ('{0:08b}'.format(oc))
				binary_list.append(binary)
			slashed = '.'.join(binary_list)
			print("Slashed mask: /",slashed.count('1'))
		except TypeError:
			return 0

if __name__ == "__main__":

	parser = optparse.OptionParser()
	parser.add_option('--ip',type="string",default=False,dest = "ipadd",help="ip address in dotted format, example: 192.168.1.1")
	parser.add_option('--mask',type="string",default=False,dest = "mask",help="subnet mask in decimal format, example: 255.255.255.0")
   
	(options,args) = parser.parse_args()
	if not options.ipadd:
		parser.error('ip address not set, please use --h for help')
	if not options.mask:
		parser.error('netmask not set, please use --h for help')

	netcalc = IPCalc()
	sub_add = netcalc.find_subnet(options.ipadd,options.mask)
	if  sub_add:
		netcalc.display_subnet(sub_add)
		range_ip = netcalc.range_ip(options.mask)
		wildcard = netcalc.find_wildcard(options.mask)
		broadcast = netcalc.find_broadcast(sub_add,wildcard)
		first_ip = netcalc.find_first(sub_add,broadcast)
		netcalc.find_last(broadcast)
		netcalc.find_slashed_mask(options.mask)

