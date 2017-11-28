import scapy.all as scapy

from socket import *

import multiprocessing

import time

import os

import MySQLdb

import re


def fun_1(packet,db,cursor):
	#########################################
	try:
		mac_addr = packet.src
	except:
		packet.show()
	
	# has type 		
	if hasattr(packet,'type')==True:
		#ARP  0x0806=2054
		if packet.type == 2054:
			ip_addr = packet['ARP'].psrc
			port = None
		#IPv4  0x800
		elif packet.type == 2048:
			try:
				ip_addr = packet['IP'].src
			except:
				#packet.show()
				exit(1)
			#	port=None
			try:
				port = packet.sport
			except:
				#packet.show()
				port=None
		#IPv6  0x86dd
		elif packet.type == 34525:
			ip_addr=None
			try:
				port = packet.sport
			except:
				packet.show()
				port = None
	#has no type
	else:
		ip_addr=None
		port=None

	pattern = re.compile(r'192\.168(\.(2[0-4]\d|25[0-5]|[01]?\d{1,2})){2}')
	r = re.match(pattern, ip_addr)
	if r == None:
		ip_addr = None

	str_port=str(port)
	#[mac_addr,ip_addr,port]
	##########################################
	#select org depend in mac_addr in MAC table
	mac=mac_addr.replace(':','')
	mac=mac[:6]

	cursor.execute('SELECT MAC_org FROM MAC WHERE MAC_id="'+mac+'"')
	#DEV_org
	MAC_org=cursor.fetchone()
	if MAC_org == None:
		MAC_org = ['noinformation',]

	##########################################
	#insert DEV_id,DEV_mac,DEV_ip,DEV_org,DEV_port into DEVICE_list_0
	# 
	#the mac_addr is exist or not in DEVICE_list_0 table
	cursor.execute('SELECT DEV_id,DEV_ip,DEV_port FROM DEVICE_list_0 WHERE DEV_mac="'+mac_addr+'"')
	mac_addr_exist=cursor.fetchone()
	if mac_addr_exist==None: # mac_addr not exist in DEVICE_list_0
		cursor.execute('insert into DEVICE_list_0(DEV_mac,DEV_ip,DEV_org,DEV_port) values("%s","%s","%s","%s")'%(mac_addr,ip_addr,MAC_org[0],str_port))
		db.commit()
	else:
		dev_id = mac_addr_exist[0]
		dev_ip = mac_addr_exist[1]
		dev_port = mac_addr_exist[2]
		if ip_addr != dev_ip:
			print "there is error(the same MAC has different IP)"
			print "%s alreay has %s \n %s" %(mac_addr,dev_ip,ip_addr)
		
		port_list = dev_port.split()
		if str_port not in port_list:
			dev_port = dev_port + ' '+ str_port
			cursor.execute('UPDATE DEVICE_list_0 SET DEV_port="%s" where DEV_id="%s"' %(dev_port,dev_id))
			db.commit()

def work_sniff():
	print 'sniff start...' 
	
	db=MySQLdb.connect('localhost','root','root','cnvd')
	cursor = db.cursor()

	cursor.execute('DROP TABLE IF EXISTS DEVICE_list_0')
	sql="""CREATE TABLE DEVICE_list_0(
        DEV_id int(5) primary key auto_increment, 
        DEV_mac VARCHAR(20), 
        DEV_ip CHAR(16),
        DEV_org CHAR(100), 
        DEV_port VARCHAR(3000)  
        )auto_increment=1"""
	cursor.execute(sql)
	
	pkts = scapy.sniff(iface='eth5',filter='src net 192.168.3 ',prn=lambda x:fun_1(x,db,cursor))

def work_p0f():
	print 'p0f start...'
	os.system('./p0f -i eth5 -o /home/mio/OOS.log')

def work_os(fpath):
	print 'read log start'
	db=MySQLdb.connect('localhost','root','root','cnvd')
	cursor = db.cursor()
	cursor.execute("DROP TABLE IF EXISTS OS")

	sql="""CREATE TABLE OS(
	       ip char(88),
	       os char(88),
	       s_time char(88))"""
	
	cursor.execute(sql)

	f_r = open(fpath,'r')
	
	if not f_r:
		print 'fail open'
	
	while True:
		line_r= f_r.readline()
		'''
		if line != '':
			print '@@@@@@@@@@@@@@@@@@@@@@@@@@@'
			print line
			re_ip=re.compile(r'cli=(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
			ips= re.findall(re_ip,line)
			ip = ips[0][4:]


			os_start=line.find('os=')
			os_end=line.find('|dist')
			os = line[os_start + 3:os_end]

			s_time = line[13:20]
			print ip,os,s_time

			#cursor.execute('SELECT * FROM OS WHERE ip="'+ip+'"')
			#ip_exist=cursor.fetchone()
			#if ip_exist== None:
			cursor.execute("insert into OS(ip,os,s_time) values('"+ip+"','"+os+"','"+s_time+"')")
			db.commit()	
			print '@@@@@@@@@@@@@@@@@@@@@@@@@@@'
		'''

		if line_r != '' and 'mod=syn|' in line_r:
			print '@@@@@@@@@@@@@@@@@@@@@@@@@@@'
			print line_r
			#re_ip=re.compile(r'cli=(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
			#ips= re.findall(re_ip,line_r)
			#ip = ips[0][4:]
			ip_start=line_r.find('cli=')
			ip_end=line_r.find('|srv=')
			ip=line_r[ip_start +4:ip_end]

			end=ip.find('/')
			ip=ip[:end]

			os_start=line_r.find('os=')
			os_end=line_r.find('|dist')
			os = line_r[os_start + 3:os_end]

			s_time = line_r[13:20]

			print ip,os,time

			cursor.execute("select * from OS where ip = '"+ip+"'")
			ip_exist=cursor.fetchone()
			if ip_exist == None:
				cursor.execute("insert into OS(ip,os,s_time) values('"+ip+"','"+os+"','"+s_time+"')")
				db.commit()	
			print '@@@@@@@@@@@@@@@@@@@@@@@@@@@'	

	'''
	f_r = open(fpath,'r')
	
	if not f_r:
		print 'fail open'
	
	while True:
		
		line_r = f_r.readline()

		if line_r != '':
			print '@@@@@@@@@@@@@@@@@@@@@@@@@@@'
			print line_r
			re_ip=re.compile(r'cli=(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
			ips= re.findall(re_ip,line_r)
			ip = ips[0][4:]

			os_start=line_r.find('os=')
			os_end=line_r.find('|dist')
			os = line_r[os_start + 3 :os_end]

			s_time = line_r[12:20]

			print ip,os,s_time

			#cursor.execute('SELECT * FROM OS WHERE ip="'+ip+'"')
			#ip_exist=cursor.fetchone()
			#if ip_exist== None:
			
			cursor.execute("insert into OS(ip,os,s_time) values('"+ip+"','"+os+"','"+s_time+"')")
			db.commit()	
			print '***********************'	
	'''	


if __name__ == "__main__":
	fpath = '/home/mio/OOS.log'

	p1 = multiprocessing.Process(target = work_p0f)
	p2 = multiprocessing.Process(target = work_sniff)
	p3 = multiprocessing.Process(target = work_os,args=(fpath,))

	p3.start()
	p1.start()
	p2.start()

