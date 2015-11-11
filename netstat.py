#!/usr/bin/python

#Author Grzegorz Wypych

import psutil
import time
import threading
import smtplib
import optparse

parser = optparse.OptionParser()

parser.add_option('--u',type="string",default=False,dest = "email",help="gmail email address")
parser.add_option('--p',type="string",default=False,dest = "passw",help="email password")
parser.add_option('--t',type="int",default=10,dest='timer',help='interval for checking opened ports')

(options,args) = parser.parse_args()
if not options.email: 
    parser.error('E-mail address is not set')
if not options.passw:
    parser.error('E-mail password is not set')
if not options.timer:
    parser.error('Interval is not set')


class Netstat:
	new_ports = 0
	def __init__(self):
		pass

#Method check listening ports in system(linux) and check if new ports has been opened

	def display_listen_conn(self):
		listen_list = []
		connection_list = []
		for conn in psutil.net_connections(kind='tcp'):
			if conn.status == 'LISTEN' and not '::' in conn.laddr[0]:
				print (conn.laddr[0]+":"+str(conn.laddr[1]))
				listen_list.append(conn.status)
				connection_list.append(str(conn.laddr[1]))

		threading.Timer(options.timer,net.display_listen_conn).start()
		print (time.ctime())
		print ("Listening ports: "),len(listen_list)
		lst_ports = int(len(listen_list))
		if self.new_ports == 0:
			self.new_ports = lst_ports
		elif self.new_ports != lst_ports:
			self.new_ports = lst_ports
			print("Number of ports changed") 
			self.email_notify(options.email,options.email,connection_list)

#Method forward email when the number of listening ports changed

	def email_notify(self,user1,user2,info):
		msg = "\r\n".join([
 		"From: "+user1,
  		"To: "+user2,
  		"Subject: Number of ports changed",
  		"",''.join('Date: '+str(time.ctime())),'LISTENING TCP PORTS:',' , '.join(info)
  		])
		server = smtplib.SMTP('smtp.gmail.com:587')
		server.ehlo()
		server.starttls()
		server.login(options.email,options.passw)
		server.sendmail(user1, user2, msg)

net = Netstat()
net.display_listen_conn()

