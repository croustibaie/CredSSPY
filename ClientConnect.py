import socket
import ssl
import hashlib
from impacket.structure import Structure
from impacket.spnego import GSSAPI, ASN1_SEQUENCE, ASN1_OCTET_STRING, asn1decode, asn1encode
from impacket import ntlm, version
from TSDecode import *
from Cryptodome.Cipher import ARC4
from OpenSSL import SSL, crypto


#Function connecting to a legitimate RDP server. Returns the ssl socket of the connection
def clientConnect(host, username, password, domain, connect = True):
    tpkt = TPKT()
    tpdu = TPDU()
    rdp_neg = RDP_NEG_REQ()
    rdp_neg['Type'] = TYPE_RDP_NEG_REQ
    rdp_neg['requestedProtocols'] = PROTOCOL_HYBRID_EX | PROTOCOL_HYBRID | PROTOCOL_SSL
    tpdu['VariablePart'] = rdp_neg.getData()
    tpdu['Code'] = TDPU_CONNECTION_REQUEST
    tpkt['TPDU'] = tpdu.getData()

    s = socket.socket()
    s.connect((host,3389))
    s.sendall(tpkt.getData())
    pkt = s.recv(8192)
    tpkt.fromString(pkt)
    tpdu.fromString(tpkt['TPDU'])
    cr_tpdu = CR_TPDU(tpdu['VariablePart'])
    if cr_tpdu['Type'] == TYPE_RDP_NEG_FAILURE:
        rdp_failure = RDP_NEG_FAILURE(tpdu['VariablePart'])
        rdp_failure.dump()
        logging.error("Server doesn't support PROTOCOL_HYBRID, hence we can't use CredSSP to check credentials")
        return
    else:
           rdp_neg.fromString(tpdu['VariablePart'])

#Here we start the SPNEGO exchange

#Step1 : Start the SSL connection 
    ctx = SSL.Context(SSL.TLSv1_2_METHOD)
    ctx.set_cipher_list('RC4,AES')
    tls = SSL.Connection(ctx,s)
    tls.set_connect_state()
    tls.do_handshake()



#Step2: Send the SPNEGO handshake
    auth = ntlm.getNTLMSSPType1('','',True, use_ntlmv2 = True)
    
    ts_request = TSRequest()
    ts_request['NegoData'] = auth.getData()
    
    tls.send(ts_request.getData())
    buff = tls.recv(4096)
    ts_request.fromString(buff)

#Step3: We should have an NTLM Challenge. Answer the challenge and sign the server pubkey
    
    lmhash =''
    nthash=''
    type3, exportedSessionKey = ntlm.getNTLMSSPType3(auth, ts_request['NegoData'], username, password, domain, lmhash, nthash, use_ntlmv2 = True)
    # Get server public key
    server_cert =  tls.get_peer_certificate()
    pkey = server_cert.get_pubkey()
    dump = crypto.dump_privatekey(crypto.FILETYPE_ASN1, pkey)

    # Fix up due to PyOpenSSL lack for exporting public keys
    dump = dump[7:]
    pubKeyStr = b'\x30'+ asn1encode(dump)
    clientNonce = "A"*32
    magic = b"CredSSP Client-To-Server Binding Hash\x00"
    h2 = hashlib.sha256()
    h2.update(magic)
    h2.update(clientNonce)
    h2.update(pubKeyStr)
    
    cipher = SPNEGOCipher(type3['flags'], exportedSessionKey)
    signature, cripted_key = cipher.clientEncrypt(h2.digest())
    ts_request['NegoData'] = type3.getData()
    ts_request['clientNonce']=clientNonce
    ts_request['pubKeyAuth'] = signature.getData() + cripted_key
    try:
        # Sending the Type 3 NTLM blob
        tls.send(ts_request.getData())
        buff = tls.recv(1024)
    except Exception as err:
        if str(err).find("denied") > 0:
            logging.error("Access Denied")
        else:
            print(err)
        return

#Step4: Server should send its pubkey signature.

    try :
        ts_request = TSRequest(buff)
        #if password is invalid buff can't be decode
        # Now we're decrypting the certificate + 1 sent by the server. Not worth checking ;)
        signature, plain_text = cipher.decrypt(ts_request['pubKeyAuth'])
    except Exception as err:
        return 0

#Step5: Send the encrypted credentials to the server
    if connect == True :
        tsp = TSPasswordCreds()
        tsp['domainName'] = domain
        tsp['userName']   = username
        tsp['password']   = password
        tsc = TSCredentials()
        tsc['credType'] = 1 # TSPasswordCreds
        tsc['credentials'] = tsp.getData()
        signature, cripted_creds = cipher.clientEncrypt(tsc.getData())
        ts_request = TSRequest()
        ts_request['authInfo'] = signature.getData() + cripted_creds
        tls.send(ts_request.getData())
        print "Credentials sent"
        return tls
    else :
        return 1

