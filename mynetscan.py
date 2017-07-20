#!/usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
from scapy.all import IP,ICMP,ARP,sr1,srp1
import time
import threading

start=time.time()

def changebin(num):
    bin1=bin(num)[2:]
    lenbin=len(bin1)
    if lenbin<8:
        l=8-lenbin
        bin2='0'*l+bin1
    else:
        bin2=bin1
    return bin2

def changeten(num):
    bin1=num[:8]
    bin2=num[8:16]
    bin3=num[16:24]
    bin4=num[24:]
    ten1=int(bin1,2)
    ten2=int(bin2,2)
    ten3=int(bin3,2)
    ten4=int(bin4,2)
    ten=str(ten1)+'.'+str(ten2)+'.'+str(ten3)+'.'+str(ten4)
    return ten

def scanping(ip):
    pkt=IP(dst=ip)/ICMP()
    ans=sr1(pkt,timeout=1)
    if ans:
        listnet1.append(ans.src)
    else:
        listnet2.append(ip)
def scanarp(ip):
    pkt=ARP(pdst=ip)
    ans=sr1(pkt,timeout=1)
    if ans:
        listnet1.append((ans.hwsrc,ans.psrc))
    else:
        listnet2.append(('None',ip))
    

listnet1=[]
listnet2=[]
try:
    if len(sys.argv)<3 or sys.argv[2]=='-h':
        print "Please input (-ping <ip>)/(<ip> -b <netmask>)/(-arp <ip>)"
        print "e.g. -ping/-arp 192.168.1.1-100"
        sys.exit(1)
    if sys.argv[1]=='-ping'and len(sys.argv)==3:
	ip=sys.argv[2]
	listip=ip.split('.')
	lastip=listip[3]
        if '-' not in lastip:
            scanping(ip)
            if listnet1:
                print '[+] ping online'+'-->'+' IP: '+listnet1[0]
            else:
	        print '[-] ping offline'+'-->'+' IP: '+listnet2[0]
            print 'Exit the system!'
            sys.exit(1) 
	listlastip=lastip.split('-')
	a=listlastip[0]
	b=listlastip[1]
	threads=[]
	if int(a)<int(b):
	    for i in xrange(int(a),int(b)+1):
	        scanip=listip[0]+'.'+listip[1]+'.'+listip[2]+'.'+'%d'%i
	        t=threading.Thread(target=scanping,args=(scanip,))
	        threads.append(t)
	    for tt in threads:
	        tt.setDaemon(True)
	        tt.start()
            for tt in threads:
		tt.join()
	    time.sleep(2)
	    print '---------------------------------------------------------------------------'
	    for i in listnet2:
	        print '[-] ping offline'+'-->'+' IP: '+i
	    for i in listnet1:
	        print '[+] ping online'+'-->'+' IP: '+i
	    print 'ping device %d online'%len(listnet1)  
	    end=time.time()
	    print 'Used time %.2f s'%(end-start)
	    print 'from '+'_'+a+'_'+'  >>>  '+' to '+'_'+b+'_'
	    print '----------------------------------------------------------------------------'
	else:
	    print 'IP.a-b,must be a<b'
    elif sys.argv[2]=='-b' and len(sys.argv)==4:
	num=sys.argv[3]
	iphost=sys.argv[1]
	listiphost=iphost.split('.')
	print "netmask:",num
	bin_ip=""
	for h in listiphost:
	    bin_ip+=str(changebin(int(h)))
	hoststartip=bin_ip[:int(num)]+'0'*(32-int(num))
	hostendip=bin_ip[:int(num)]+'1'*(32-int(num))
	print changeten(hoststartip),'===>',changeten(hostendip)
	sys.exit(1)
    elif sys.argv[1]=='-arp' and len(sys.argv)==3:
       	ip=sys.argv[2]
	listip=ip.split('.')
	lastip=listip[3]
        if '-' not in lastip:
            scanarp(ip)
            if listnet1:
                print '[+] ARP online'+'-->'+' MAC: '+listnet1[0][0]+' <= AND =>'+' IP: '+listnet1[0][1]
            else:
	        print '[-] ARP offline'+'-->'+' MAC: '+listnet2[0][0]+' <= AND =>'+' IP: '+listnet2[0][1]
            print 'Exit the system!'
            sys.exit(1) 
	listlastip=lastip.split('-')
	a=listlastip[0]
	b=listlastip[1]
        threads=[]
	if int(a)<int(b):
	    for i in xrange(int(a),int(b)+1):
	        scanip=listip[0]+'.'+listip[1]+'.'+listip[2]+'.'+'%d'%i
	        t=threading.Thread(target=scanarp,args=(scanip,))
	        threads.append(t)
	    for tt in threads:
	        tt.setDaemon(True)
	        tt.start()
	    for tt in threads:
		tt.join()
	    time.sleep(2)
	    print '---------------------------------------------------------------------------'
	    for i in listnet2:
                print '[-] ARP offline'+'-->'+' MAC: '+i[0]+' <= AND =>'+' IP: '+i[1]
	    for i in listnet1:
	        print '[+] ARP online'+'-->'+' MAC: '+i[0]+' <= AND =>'+' IP: '+i[1]
	    print 'ARP device %d online'%len(listnet1)  
	    end=time.time()
	    print 'Used time %.2f s'%(end-start)
	    print 'from '+'_'+a+'_'+'  >>>  '+' to '+'_'+b+'_'
	    print '----------------------------------------------------------------------------'
	else:
	    print 'IP.a-b,must be a<b'

		
    else:
	print "Please input (-ping <ip>)/(<ip> -b <netmask>)/(-arp <ip>)"
        print "e.g. -ping/-arp 192.168.1.1-100"
        sys.exit(1)

except Exception,e:
    print e




