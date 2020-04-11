from binascii import unhexlify, hexlify
from impacket.spnego import *
from impacket import ntlm, version
from impacket.ntlm import *
from impacket.structure import Structure

class NTLMType2(Structure):

    structure = (
            ('header',':'),
            ('message_type',"<L"),
            ('targetNameSecLen', '<H'),
            ('targetNameSecAll', '<H'),
            ('targetNameSecOff', '<L'),
            ('flags', '<L'),
            ('challenge','8s'),
            ('context', '8s'),
            ('targetInfoSecLen','<H'),
            ('targetInfoSecAll','<H'),
            ('targetInfoSecOff','<L'),
            ('targetName',':'),
            ('targetInfoType2','<H'),
            ('targetInfoDomainNameLen','<H',),
            ('targetInfoDomainName',':',),
            ('targetInfoType1','<H'),
            ('targetInfoServerNameLen','<H'),
            ('targetInfoServerName',':'),
            ('targetInfoType4','<H'),
            ('targetInfoDNSDomainNameLen','<H'),
            ('targetInfoDNSDomainName',':'),
            ('targetInfoType3','<H'),
            ('targetInfoDNSServerNameLen','<H'),
            ('targetInfoDNSServerName',':'),
            ('terminatorBlock','<L'),
            )

    def __init__(self):
        Structure.__init__(self)
        self['header'] = "NTLMSSP\x00"
        self['message_type'] = 0x00000002
        self['targetNameSecLen'] = 0x0000
        self['targetNameSecAll'] = 0x0000
        self['targetNameSecOff'] = 0x0000000030
        self['flags']= 0xe2898235
        self['targetInfoSecLen']= 0x0000
        self['targetInfoSecAll']= 0x0000
        self['targetInfoSecOff']= 0x0000000050
        self['challenge']='AAAAAAAA'
        self['context']= 8*"\x00"
        self['targetInfoSec']=''
        self['targetName']=''
        self['targetInfoType2']=0x0002
        self['targetInfoDomainNameLen']=0x0000
        self['targetInfoDomainName']=''
        self['targetInfoType1']=0x0001
        self['targetInfoServerNameLen']=0x0000
        self['targetInfoServerName']= ''
        self['targetInfoType4']=0x0004
        self['targetInfoDNSDomainNameLen']=0x0000
        self['targetInfoDNSDomainName']=''
        self['targetInfoType3']=0x0003
        self['targetInfoDNSServerNameLen']=0x000
        self['targetInfoDNSServerName']=''
        self['terminatorBlock']= 0x00000000

    def getData(self):
        return Structure.getData(self)


def getNTLMSSPType2(server,domain,dnsdomain):
    import sys
    encoding = sys.getfilesystemencoding()
    if encoding is not None:
        try:
            server = server.encode('utf-16le')
        except:
            server = server.decode(encoding)
        try:
            domain = domain.encode('utf-16le')
        except:
            domain = domain.decode(encoding)
        try:
            dnsdomain = dnsdomain.encode('utf-16le')
        except:
            dnsdomain = dnsdomain.decode(encoding)

    type2 = NTLMType2()
    type2['targetName'] = domain.upper()
    type2['targetNameSecLen'] = len(type2['targetName'])
    type2['targetNameSecAll'] = len(type2['targetName'])
    type2['targetInfoDomainName'] = domain.upper()
    type2['targetInfoDomainNameLen'] = len(type2['targetInfoDomainName'])
    type2['targetInfoServerName'] = server.upper()
    type2['targetInfoServerNameLen'] = len(type2['targetInfoServerName'])
    type2['targetInfoDNSDomainName'] = dnsdomain.lower()
    type2['targetInfoDNSDomainNameLen'] = len(type2['targetInfoDNSDomainName'])
    type2['targetInfoDNSServerName'] = server.lower() + ".\x00" + dnsdomain.lower()
    type2['targetInfoDNSServerNameLen'] = len(type2['targetInfoDNSServerName'])
    type2['targetInfoSecLen'] = type2['targetInfoDomainNameLen'] + 4 + len(type2['targetInfoServerName']) + 4 + len(type2['targetInfoDNSDomainName']) + 4 + len(type2['targetInfoDNSServerName']) + 4 + 4
    type2['targetInfoSecAll'] = type2['targetInfoSecLen']
    type2['targetInfoSecOff'] = type2['targetNameSecOff'] + type2['targetNameSecLen']
    return type2
