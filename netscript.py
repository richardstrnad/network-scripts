#!/usr/bin/env/python

import optparse
import queue
import threading
import paramiko
import time
import socket
from datetime import datetime
import signal
import sys

''' Overall parser used in command line menu'''

print(("="*64))
print ("\tGrzegorz Wypych (horac)")
print ("\tTested on Cisco CSR 1000v and Juniper vSRX")
print(("="*64))
print ("\t To stop the script please use CTRL+C")
print(("="*64))
parser = optparse.OptionParser()
parser.add_option('-f',default=False,dest = "sfile",help="Required to select file with devices")
parser.add_option('-u',default=False,dest = "user",help="Required username for SSH connection")
parser.add_option('-p',default=False,dest = "passw",help="Required password for SSH connection")
get_opts = optparse.OptionGroup(parser,'Get options','This options are use to retrieve information from device')
get_opts.add_option('-b',action='store_true',default=False,dest = "basic",help="Option used to get Serial,Model,Interface List,Hostname") 

config_opts = optparse.OptionGroup(parser,'Configuration options','This options are use to configure device') 
config_opts.add_option('--host',action='store_true',dest = "hostname",help="Do not require argument, change hostnames on devices, base on input device file")   
config_opts.add_option('--snmp',default=False,dest = "snmpc",help="Configure SNMP community, example: --snmp test")
config_opts.add_option('--ntp',type='string',default=False,dest = "ntps",help="Configure NTP server, example: --ntp 1.1.1.1")
config_opts.add_option('--en',type ='string',default=False,dest = "enable",help="Required for Cisco enable password (could be empty if not last arg), ignored on Juniper device")

parser.add_option_group(get_opts)
parser.add_option_group(config_opts)

(opt,args) = parser.parse_args()

''' Basic check for FILE input and user and password to be able to log to device '''

if not opt.sfile:
	parser.error('file with IP addresses of devices missing, please use -h for help')
if not opt.user:
	parser.error('username required for SSH connection, please use -h for help')
if not opt.passw:
	parser.error('password required for SSH connection, please use -h for help')
#if not opt.basic and not opt.enable:
	#parser.error('Required enable or basic or both, please use -h for help')


''' Global function used to validate IP address for NTP'''

def validate_ip(address):
	try:
		valid_ip = []
		parts = address.split(".")
		if len(parts) != 4:
			parser.error("[-] IPv4 address has 4 octes")
		for item in parts:
			if not 0 <= int(item) <= 255:
				parser.error("[-] Invalid IPv4 address")
			valid_ip.append(item)
		return '.'.join(valid_ip)
	except ValueError:
		parser.error("[-] This is not IPv4 address")

'''Validation for NTP IP'''

if opt.ntps:
	opt.ntps = validate_ip(opt.ntps)

''' Main class used for connection '''

class Device(object):

	def __init__(self):

		''' Class fields '''

		self.dfile = ''
		self.devices = []
		self.device_queue = queue.Queue()
		self.ssh = paramiko.SSHClient()
		self.remote_conn = ''
		self.lock = threading.Lock()
		self.hostnames = ''
		self.host_list = []
		self.prompt = ''
		self.juniper = False
		self.EXEC = '>'
		self.PRIV = '#'
		self.CONFIG = '(config)'

		'''Read file method responsible for reading the input file and creating list IP,hostname'''

	def read_file(self):
		try:
			self.dfile = open(opt.sfile,'r')
			data = self.dfile.readlines()
			for ip in data:
				ip = ip.strip().split(',')
				self.devices.append(ip)
			return self.devices
		except IOError:
			print ("[-] Problem with file reading or file not exist")
			sys.exit(0)

		''' Fill queue metod resposible of creating Queue with IP and Hostname base on input file'''

	def fill_device_queue(self,devices):
		devices = self.devices
		for i in range(0,len(devices)):
			self.device_queue.put(devices[i])
		return self.device_queue

		''' Core Function that opens SSH to devices, and detects command line options, also detects device type
			SSH keys are not verified base on ~/.ssh/known_hosts,'''	

	def open_connection(self,devices):
		self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		while not self.device_queue.empty():
			device = self.device_queue.get()
			try:
				self.lock.acquire()
				self.ssh.connect(device[0], username=opt.user, password=opt.passw,timeout=1, look_for_keys=False, allow_agent=False)
				print(("[+] %s open ssh connection to %s"%(str(datetime.now()),device[0])))
				print(("Thread: ",threading.currentThread()))
				self.remote_conn = self.ssh.invoke_shell(term='vt100')
				if self.remote_conn:
					time.sleep(1)
					output = self.wait_for_output(self.EXEC)
					temp = output.splitlines()
					self.prompt = temp[-1]
					if self.EXEC in self.prompt:
						print ("[+] Detecting device vendor")
						self.remote_conn.send('request\n')
						output = self.wait_for_output(self.EXEC)
						if "syntax" in output:
							print (output)
							print ("[+] Juniper device detected")
							self.juniper = True
						if "%" in output:
							print (output)
							print ("[+] Cisco device detected")
							self.juniper = False
					
					if self.juniper == True:
						if opt.basic and not (opt.enable or opt.ntps or opt.snmpc or opt.hostname):
							#print "First condition 1"					
							self.retrieve_juniper_comm()
						elif (opt.basic or opt.enable) and not(opt.ntps or opt.snmpc or opt.hostname):
							#print "Second condition 2"
							self.retrieve_juniper_comm()
						elif (opt.ntps or opt.snmpc or opt.hostname) and opt.enable:
							#print "Third condition 3"
							if opt.basic:
								self.retrieve_juniper_comm()
							if len(device) == 2 and opt.hostname:
								self.configure_juniper_hostname(device[1])
							self.configure_other_juniper_params()

					if self.juniper == False:	
						if (opt.ntps or opt.snmpc or opt.hostname) and opt.enable:
							#print "First condition 1"
							if opt.basic:
								self.retrieve_cisco_comm()
							if self.do_enable():
								if len(device) == 2 and opt.hostname:
									self.configure_cisco_hostname(device[1])
								self.configure_other_cisco_params()
						elif (opt.ntps or opt.snmpc or opt.hostname) and opt.enable:
							#print "Second condition 2"
							if self.do_enable():
								if len(device) == 2 and opt.hostname:
									self.configure_cisco_hostname(device[1])
								self.configure_other_cisco_params()
						elif opt.basic and not opt.enable:
							#print "Third condition 3"
							self.retrieve_cisco_comm()
							if opt.ntps or opt.snmpc or opt.hostname:
								if self.do_enable():
									if len(device) ==2 and opt.hostname:
										self.configure_cisco_hostname(device[1])
									self.configure_other_cisco_params()
						elif opt.basic or opt.enable:
							#print "fourth Condition 4"
							if self.do_enable():
								self.retrieve_cisco_comm()	
							else:
								self.retrieve_cisco_comm()
					if self.EXEC in self.prompt and not opt.enable and not opt.basic:
						#print "fifth Condition 5"
						if opt.ntps or opt.snmpc or opt.hostname and self.PRIV not in self.prompt:
							if self.juniper == False:
								print ("[+] Configuration not allowed in exec mode")
								self.remote_conn.send('exit\n')

							elif self.juniper == True:
								if len(device) == 2 and opt.hostname:
									self.configure_juniper_hostname(device[1])
								self.configure_other_juniper_params()
				else:
					self.ssh.close()
			except (paramiko.ssh_exception.SSHException,paramiko.SSHException,paramiko.AuthenticationException,socket.error,socket.timeout,socket.gaierror) as error:
					print(("[-] %s Problem with SSH connection to device %s, reason %s: "%(str(datetime.now()),device[0],error)))
					pass
			self.lock.release()
		return self.remote_conn

	'''Method below retrieve information from cisco device - CSR 1000v'''

	def retrieve_cisco_comm(self):
		self.remote_conn.send("show inventory\n")
		output = self.wait_for_output(self.EXEC)
		if self.EXEC or self.PRIV in output:
			output = output.splitlines()
		new_out  = [] 
		for i in range(0,len(output)):
			new_out.append(output[i].split())
		model = new_out[1][-2]
		serial = new_out[2][-1]		
		self.remote_conn.send("show ver | in up\n")
		output = self.wait_for_output(self.EXEC)
		host = output.splitlines()[-2]
		host = host.split()
		self.remote_conn.send("terminal length 0\n")
		term = self.wait_for_output(self.EXEC)
		self.remote_conn.send("show ip int brief\n")
		inter = self.wait_for_output(self.EXEC)	
		print(("=" * 64))
		print ('\t Retrieve requested information about Cisco device')
		print(("=" * 64))
		print(('Model:\t\t'+model))
		print(('Serial:\t\t'+serial))
		print(('Hostname:\t'+host[0]))
		print(("=" * 64))
		print ('\t Cisco device interface information')
		self.parse_cisco_interfaces(inter)

	'''Function is used to parse cisco show ip int brief '''

	def parse_cisco_interfaces(self,inter):
		interfaces = []
		inter =  inter.splitlines()
		inter  = inter[2:-1]
		for i in range(0,len(inter)):
			interfaces.append(inter[i].split())
		#print interfaces
		'''
		temp =[]
		for i in xrange(0,len(interfaces)):
			for y in xrange(0,len(interfaces[i])):
				if interfaces[i][y] != 'YES':
					temp.append(interfaces[i][y])
		'''
		temp = [y for x in interfaces for y in x if y !='YES'] 
		interfaces = temp
		#print interfaces
		keys = ['Interface', 'IP address', 'Method', 'Line', 'Protocol']
		interfaces = list(zip(*[iter(interfaces)]*5))
		interfaces = [dict(list(zip(keys,value))) for value in interfaces]
		for i in range(0,len(interfaces)):
			print((64 *"="+'\n'))
			for key,value in list(interfaces[i].items()):
				print(('# '+key+': '+value))
		print((64*"="))


	
	def retrieve_juniper_comm(self):
		self.remote_conn.send("show version\n")
		time.sleep(1)
		output = self.wait_for_output(self.EXEC)
		if self.EXEC in output:
			output = output.splitlines()
		#print output
		new_out = []
		for i in range(0,len(output)):
			new_out.append(output[i].split())
		host = new_out[1][0].replace(':','')
		name = new_out[1][1]
		model = new_out[2][0].replace(':','')
		value = new_out[2][1]
		self.remote_conn.send("show chassis hardware | grep Chassis\n")
		output = self.wait_for_output(self.EXEC)
		if self.EXEC in output:
			output = output.splitlines()
		sent = []
		for x in range(0,len(output)):
			sent.append(output[x].split())
		sent = sent [1:-2]
		sent = sent[0][:-1]
		sent[0] = 'Serial'
		print(("=" * 64))
		print ('\t Retrieve requested information about Juniper device')
		print(("=" * 64))
		print((model+':\t\t'+value))
		print((sent[0]+':\t\t'+sent[1]))
		print((host+':\t'+name))
		print(("=" * 64))
		self.remote_conn.send('set cli screen-length 10000\n')
		output = self.wait_for_output(self.EXEC)
		print (output)
		self.remote_conn.send('show interfaces terse\n')
		time.sleep(0.5)
		output = self.wait_for_output(self.EXEC)
		print(("="*64))
		print ("\t Juniper device interface information")
		print(("="*64))
		print (output)
		print(("=" *64))
		

	
	'''Method below used for Cisco device configuration, base on flags from command line'''

	def configure_cisco_hostname(self,hostname):
		opt.hostname = hostname
		#print "in configure func"
		#print "prompt in conf func",self.prompt
		self.remote_conn.send("config t\n")
		print ("[+] Enter config mode")
		output = self.wait_for_output(self.CONFIG)
		print (output)
		if opt.hostname:
			print ("[+] Trying to apply new hostname")
			self.remote_conn.send('hostname '+opt.hostname+'\n')
			output = self.wait_for_output(self.CONFIG)
			host_out = output.splitlines()[::-1]
			print((host_out[0],host_out[-1]))
		self.remote_conn.send('end\n')
		output = self.wait_for_output(self.PRIV)
		print (output)
		print ("[+] Task completed")
		return 

	def configure_other_cisco_params(self):
		self.remote_conn.send("config t\n")
		print ("[+] Enter config mode")
		output = self.wait_for_output(self.CONFIG)
		print (output)
		if opt.snmpc:
			print ("[+] Trying to apply SNMP community")
			self.remote_conn.send('snmp-server community '+opt.snmpc+'\n')
			output = self.wait_for_output(self.CONFIG)
			host_out = output.splitlines()[::-1]
			print((host_out[0],host_out[-1]))
		if opt.ntps:
			print ("[+] Trying to apply NTP server")
			self.remote_conn.send('ntp server '+opt.ntps+'\n')
			output = self.wait_for_output(self.CONFIG)
			ntp_out = output.splitlines()[::-1]
			print((ntp_out[0],ntp_out[-1]))
		self.remote_conn.send('end\n')
		output = self.wait_for_output(self.PRIV)
		print (output)
		print ("[+] Task completed")
		return

	'''Method below used for Juniper device configuration, base on flags from command line '''

	def configure_juniper_hostname(self,hostname):
		opt.hostname = hostname
		self.remote_conn.send("configure\n")
		time.sleep(0.5)
		print ("[+] Enter config mode")
		output = self.wait_for_output(self.PRIV)
		#print output
		if opt.hostname:
			print ("[+] Trying to apply hostname")
			self.remote_conn.send('set system host-name '+opt.hostname+'\n')
			time.sleep(0.5)
			output = self.wait_for_output(self.PRIV)
			host_out =  output.splitlines()[::-1]
			print((host_out[0],host_out[-1]))	
			self.remote_conn.send('commit check\n')
			output = self.wait_for_output(self.PRIV)
			#print output.splitlines()
			comck = output.splitlines()[::-1]
			#print comck
			print((comck[0],comck[-1]))
			print(("[+]",comck[-2]))
			self.remote_conn.send('commit\n')
			output = self.wait_for_output(self.PRIV)
			commit = output.splitlines()[::-1]
			print((commit[0],commit[-1]))
			print((commit[0],commit[-2]))
			print ("[+] Task completed")


	def configure_other_juniper_params(self):
		self.remote_conn.send("configure\n")
		time.sleep(0.5)
		#print "[+] Enter config mode"
		output = self.wait_for_output(self.PRIV)
		print (output)
		if opt.ntps:
			print ("[+] Trying to apply NTP server")
			self.remote_conn.send('set system ntp server '+opt.ntps+'\n')
			time.sleep(0.5)
			output = self.wait_for_output(self.PRIV)
			ntp_out =  output.splitlines()[::-1]
			print((ntp_out[0],ntp_out[-1]))	
			self.remote_conn.send('commit check\n')
			output = self.wait_for_output(self.PRIV)
			#print output.splitlines()
			comck = output.splitlines()[::-1]
			#print comck
			print((comck[0],comck[-1]))
			print(("[+]",comck[-2]))
			self.remote_conn.send('commit\n')
			output = self.wait_for_output(self.PRIV)
			commit = output.splitlines()[::-1]
			print((commit[0],commit[-1]))
			print((commit[0],commit[-2]))
			print ("[+] Task completed")
			#self.remote_conn.send('exit\n')
		if opt.snmpc:
			print ("[+] Trying to apply SNMP community")
			self.remote_conn.send('set snmp community '+opt.snmpc+'\n')
			time.sleep(0.5)
			output = self.wait_for_output(self.PRIV)
			print (output)
			snmp_out =  output.splitlines()[::-1]
			print((snmp_out[0],snmp_out[-1]))
			self.remote_conn.send('commit check\n')
			output = self.wait_for_output(self.PRIV)
			#print output.splitlines()
			comck = output.splitlines()[::-1]
			#print comck
			print((comck[0],comck[-1]))
			print(("[+]",comck[-2]))
			self.remote_conn.send('commit\n')
			output = self.wait_for_output(self.PRIV)
			commit = output.splitlines()[::-1]
			print((commit[0],commit[-1]))
			print((commit[0],commit[-2]))
			print ("[+] Task completed")
			#self.remote_conn.send('exit\n')
	
	'''Method checks enable password for Cisco device and returns Privledge mode prompt if succeeded'''

	def do_enable(self):
		output = ''
		self.remote_conn.send('enable\n')
		output = self.wait_for_password()
		if not "ERROR" in output:
			if opt.enable:
				self.remote_conn.send(opt.enable+'\n')
				output = self.wait_for_enable()
				if not "ERROR" in output:
					print ("[+] Enable password correct")
					temp = output.splitlines()
					self.prompt = temp[-1]
					print((self.prompt))
					if '#' in self.prompt:
						#print "True returned"
						return True
				else:
					print ("[-] Enable failed")
					return False
		if '#' in self.prompt:
				return True
						
	'''Core method used to check prompts each time when command is sent
	   Includes while loop that recievs packets and check prompt '''

	def wait_for_output(self,new_prompt):
		complete = False
		temp = ''
		packet = ''
		while not complete:
			packet += self.remote_conn.recv(65535).decode()
			#print "IN WAIT FOR OUTPUT PROMPT: ",self.prompt
			'''!!!! print packet important for debbuging problems !!!'''
			#print packet				
			if new_prompt in packet:
				self.prompt = new_prompt
				#print "NEW_PROMPT:",self.prompt
				complete = True
			if self.prompt in packet:
				#print "Error"
				#print "SELF PROMPT:",self.prompt
				complete = True
		#print packet
		return packet

	'''Method used to check if "Password" appears after enable command'''

	def wait_for_password(self):
		complete = False
		temp = ''
		packet = ''
		#print "wait_for_password"
		while not complete:
			packet += self.remote_conn.recv(65535).decode()
			#print "PACKET: ",packet
			if "Password" in packet:
				complete = True
			if "%" in packet:
				complete = True
				return "ERROR"
			if "#" in packet:
				complete =True
		#print packet
		return packet

	'''Method checks prompt for enable password'''
	
	def wait_for_enable(self):
		complete = False
		temp = ''
		packet = ''
		#print "wait_for_password"
		while not complete:
			packet += self.remote_conn.recv(65535).decode()
			#print "PACKET: ",packet
			if "#" in packet:
				complete = True
			if ">" in packet:
				complete = True
				return "ERROR"
		return packet
	

	'''Main program begins, Program includes 4 Threads spread between SSH connections which get each connection
	   from device Queue'''

if __name__ == '__main__':

	dev = Device()
	devices = dev.read_file()
	if devices:
		print ("[+] File with devices detected")
		dev.fill_device_queue(devices)
		for i in range(4):
			t = threading.Thread(target=dev.open_connection,args=(devices ,))
			t.setDaemon(True)
			t.start()
		
	try:
		while threading.active_count() > 0:
			time.sleep(0.1)
	except KeyboardInterrupt:
			print ("[+] Exited from script")
	
