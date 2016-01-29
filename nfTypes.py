import ctypes
import ipaddress
import binascii
import socket
import collections

hexList = ['00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0A', '0B', '0C', '0D', '0E', '0F', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1A', '1B', '1C', '1D', '1E', '1F', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2A', '2B', '2C', '2D', '2E', '2F', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3A', '3B', '3C', '3D', '3E', '3F', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4A', '4B', '4C', '4D', '4E', '4F', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5A', '5B', '5C', '5D', '5E', '5F', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6A', '6B', '6C', '6D', '6E', '6F', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7A', '7B', '7C', '7D', '7E', '7F', '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8A', '8B', '8C', '8D', '8E', '8F', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9A', '9B', '9C', '9D', '9E', '9F', 'A0', 'A1', 'A2', 'A3', 'A4', 'A5', 'A6', 'A7', 'A8', 'A9', 'AA', 'AB', 'AC', 'AD', 'AE', 'AF', 'B0', 'B1', 'B2', 'B3', 'B4', 'B5', 'B6', 'B7', 'B8', 'B9', 'BA', 'BB', 'BC', 'BD', 'BE', 'BF', 'C0', 'C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8', 'C9', 'CA', 'CB', 'CC', 'CD', 'CE', 'CF', 'D0', 'D1', 'D2', 'D3', 'D4', 'D5', 'D6', 'D7', 'D8', 'D9', 'DA', 'DB', 'DC', 'DD', 'DE', 'DF', 'E0', 'E1', 'E2', 'E3', 'E4', 'E5', 'E6', 'E7', 'E8', 'E9', 'EA', 'EB', 'EC', 'ED', 'EE', 'EF', 'F0', 'F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'FA', 'FB', 'FC', 'FD', 'FE', 'FF']


def getTextAddr(value):
    return hexList[value[0]] + hexList[value[1]] + ":" + \
           hexList[value[2]] + hexList[value[3]] + ":" + \
           hexList[value[4]] + hexList[value[5]] + ":" + \
           hexList[value[6]] + hexList[value[7]] + ":" + \
           hexList[value[8]] + hexList[value[9]] + ":" + \
           hexList[value[10]] + hexList[value[11]] + ":" + \
           hexList[value[12]] + hexList[value[13]] + ":" + \
           hexList[value[14]] + hexList[value[15]]

def getTypeFunc(dataType, length):
    result = None
    if dataType == "uint":
        if length == 1:
            result = ctypes.c_uint8
        elif length == 2:
            result = ctypes.c_uint16
        elif length == 4:
            result = ctypes.c_uint32
        elif length == 8:
            result = ctypes.c_uint64
    elif dataType == "int":
        if length == 1:
            result = ctypes.c_int8
        elif length == 2:
            result = ctypes.c_int16
        elif length == 4:
            result = ctypes.c_int32
        elif length == 8:
            result = ctypes.c_int64
    elif dataType == "float":
        if length == 4:
            result = ctypes.c_float
        elif length == 8:
            result = ctypes.c_double
    elif dataType == "string":
        result = ctypes.c_char * length
    elif dataType == "ipv4Address":
        result = ctypes.c_ubyte * 4
    elif dataType == "ipv6Address":
        result = ctypes.c_ubyte * 16
    
    if result:
        return result
    else:
        raise "Invalid data type or length: " + dataType + ", " + str(length)

    
class metaIE(type):
    registry = collections.OrderedDict()
    def __new__(cls, name, bases, attrs):
        new_cls = type.__new__(cls, name, bases, attrs)
        eID = attrs['elementID']
        if eID > 0:
            cls.registry[eID] = new_cls
        return new_cls

        
class informationElement(object):
    __metaclass__ = metaIE
    elementID = 0
    
    def __init__(self, length):
        self.length = length
        if self.elementID > 0:
            self.seeType = getTypeFunc(self.baseType, length)
    
    def getPyVal(self, value):
        return value    

class octetDeltaCount(informationElement):
    names = ["IN_BYTES", "octetDeltaCount"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 1
    baseType = "uint"
    pyType = int
        
class packetDeltaCount(informationElement):
    names = ["IN_PKTS", "packetDeltaCount"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 2
    baseType = "uint"
    pyType = int

class protocolIdentifier(informationElement):
    names = ["PROTOCOL", "protocolIdentifier"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 4
    baseType = "uint"
    pyType = int
    
class ipClassOfService(informationElement):
    names = ["TOS","ipClassOfService"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 5
    baseType = "uint"
    pyType = int
    
class tcpControlBits(informationElement):
    names = ["TCP_FLAGS","tcpControlBits"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 6
    baseType = "uint"
    pyType = int

class sourceTransportPort(informationElement):
    names = ["L4_SRC_PORT","sourceTransportPort"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 7
    baseType = "uint"
    pyType = int

class sourceIPv4Address(informationElement):
    names = ["IPV4_SRC_ADDR","sourceIPv4Address"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 8
    baseType = "ipv4Address"
    pyType = ipaddress.IPv4Address
    
    def getPyVal(self, value):
        return socket.inet_ntoa(value)

class ingressInterface(informationElement):
    names = ["INPUT_SNMP","ingressInterface"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 10
    baseType = "uint"
    pyType = int

class destinationTransportPort(informationElement):
    names = ["L4_DST_PORT","destinationTransportPort"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 11
    baseType = "uint"
    pyType = int
    
class destinationIPv4Address(informationElement):
    names = ["IPV4_DST_ADDR","destinationIPv4Address"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 12
    baseType = "ipv4Address"
    pyType = ipaddress.IPv4Address
    
    def getPyVal(self, value):
        return socket.inet_ntoa(value)
        
class egressInterface(informationElement):
    names = ["OUTPUT_SNMP","egressInterface"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 14
    baseType = "uint"
    pyType = int
    
class flowEndSysUpTime(informationElement):
    names = ["LAST_SWITCHED","flowEndSysUpTime"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 21
    baseType = "uint"
    pyType = int

class flowStartSysUpTime(informationElement):
    names = ["FIRST_SWITCHED","flowStartSysUpTime"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 22
    baseType = "uint"
    pyType = int

class sourceIPv6Address(informationElement):
    names = ["IPV6_SRC_ADDR","sourceIPv6Address"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 27
    baseType = "ipv6Address"
    pyType = ipaddress.IPv6Address

    def getPyVal(self, value):
        return getTextAddr(value)
        
class destinationIPv6Address(informationElement):
    names = ["IPV6_DST_ADDR","destinationIPv6Address"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 28
    baseType = "ipv6Address"
    pyType = ipaddress.IPv6Address

    def getPyVal(self, value):
        return getTextAddr(value)
        
class icmpTypeCodeIPv4(informationElement):
    names = ["ICMP_TYPE","icmpTypeCodeIPv4"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 32
    baseType = "uint"
    pyType = int

class flowDirection(informationElement):
    names = ["DIRECTION","flowDirection"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 61
    baseType = "uint"
    pyType = int

class flowId(informationElement):
    names = ["flowId","flowId"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 148
    baseType = "uint"
    pyType = int

class postNATSourceIPv4Address(informationElement):
    names = ["postNATSourceIPv4Address","postNATSourceIPv4Address"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 225
    baseType = "ipv4Address"
    pyType = ipaddress.IPv4Address

    def getPyVal(self, value):
        return socket.inet_ntoa(value)
    
class postNATDestinationIPv4Address(informationElement):
    names = ["postNATDestinationIPv4Address","postNATDestinationIPv4Address"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 226
    baseType = "ipv4Address"
    pyType = ipaddress.IPv4Address

    def getPyVal(self, value):
        return socket.inet_ntoa(value)    
    
class postNAPTSourceTransportAddress(informationElement):
    names = ["postNAPTSourceTransportAddress","postNAPTSourceTransportAddress"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 227
    baseType = "uint"
    pyType = int

class postNAPTDestinationTransportAddress(informationElement):
    names = ["postNAPTDestinationTransportAddress","postNAPTDestinationTransportAddress"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 228
    baseType = "uint"
    pyType = int
  
class firewallEvent(informationElement):
    names = ["firewallEvent","firewallEvent"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 233
    baseType = "uint"
    pyType = int

class postNATSourceIPv6Address(informationElement):
    names = ["postNATSourceIPv6Address","postNATSourceIPv6Address"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 281
    baseType = "ipv6Address"
    pyType = ipaddress.IPv6Address

    def getPyVal(self, value):
        return getTextAddr(value)
        
class postNATDestinationIPv6Address(informationElement):
    names = ["postNATDestinationIPv6Address","postNATDestinationIPv6Address"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 282
    baseType = "ipv6Address"
    pyType = ipaddress.IPv6Address

    def getPyVal(self, value):
        return getTextAddr(value)  
    
class privateEnterpriseNumber(informationElement):
    names = ["privateEnterpriseNumber","privateEnterpriseNumber"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 346
    baseType = "uint"
    pyType = int

class appID(informationElement):
    names = ["App-ID","App-ID"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 56701
    baseType = "string"
    pyType = str

class userID(informationElement):
    names = ["User-ID","User-ID"]
    nf9name = names[0]
    ipfixName = names[1]
    elementID = 56702
    baseType = "string"
    pyType = str
