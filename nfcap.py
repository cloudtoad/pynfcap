import socket, select, struct, collections, ipaddress, nfTypes, ctypes, time, os, csv, yaml, hiyapyco, profile


fileWindow = 3600
fileAgeOut = 86400

fieldIndex = {'postNAPTSourceTransportAddress': 27, 'TOS': 10, 'postNATSourceIPv6Address': 30, 'IPV4_DST_ADDR': 16, 'INPUT_SNMP': 14, 'User-ID': 34, 'LAST_SWITCHED': 18, 'OUTPUT_SNMP': 17, 'DIRECTION': 23, 'IN_PKTS': 8, 'postNATDestinationIPv6Address': 31, 'FIRST_SWITCHED': 19, 'postNATSourceIPv4Address': 25, 'IPV6_DST_ADDR': 21, 'postNATDestinationIPv4Address': 26, 'TCP_FLAGS': 11, 'postNAPTDestinationTransportAddress': 28, 'PROTOCOL': 9, 'L4_SRC_PORT': 12, 'ICMP_TYPE': 22, 'IN_BYTES': 7, 'App-ID': 33, 'IPV4_SRC_ADDR': 13, 'flowId': 24, 'IPV6_SRC_ADDR': 20, 'firewallEvent': 29, 'privateEnterpriseNumber': 32, 'L4_DST_PORT': 15}
dfnames = [
    "timeReceived",
    "nfHost",
    "nfSourceID",
    "sysUpTime",
    "unixSeconds",
    "sequenceNumber",
    "flowSetID",
    "IN_BYTES",
    "IN_PKTS",
    "PROTOCOL",
    "TOS",
    "TCP_FLAGS",
    "L4_SRC_PORT",
    "IPV4_SRC_ADDR",
    "INPUT_SNMP",
    "L4_DST_PORT",
    "IPV4_DST_ADDR",
    "OUTPUT_SNMP",
    "LAST_SWITCHED",
    "FIRST_SWITCHED",
    "IPV6_SRC_ADDR",
    "IPV6_DST_ADDR",
    "ICMP_TYPE",
    "DIRECTION",
    "flowId",
    "postNATSourceIPv4Address",
    "postNATDestinationIPv4Address",
    "postNAPTSourceTransportAddress",
    "postNAPTDestinationTransportAddress",
    "firewallEvent",
    "postNATSourceIPv6Address",
    "postNATDestinationIPv6Address",
    "privateEnterpriseNumber",
    "App-ID",
    "User-ID"
]

    

dfnames = [
    "timeReceived",
    "nfHost",
    "nfSourceID",
    "sysUpTime",
    "unixSeconds",
    "sequenceNumber",
    "flowSetID",
    "IN_BYTES",
    "IN_PKTS",
    "PROTOCOL",
    "TOS",
    "TCP_FLAGS",
    "L4_SRC_PORT",
    "IPV4_SRC_ADDR",
    "INPUT_SNMP",
    "L4_DST_PORT",
    "IPV4_DST_ADDR",
    "OUTPUT_SNMP",
    "LAST_SWITCHED",
    "FIRST_SWITCHED",
    "IPV6_SRC_ADDR",
    "IPV6_DST_ADDR",
    "ICMP_TYPE",
    "DIRECTION",
    "flowId",
    "postNATSourceIPv4Address",
    "postNATDestinationIPv4Address",
    "postNAPTSourceTransportAddress",
    "postNAPTDestinationTransportAddress",
    "firewallEvent",
    "postNATSourceIPv6Address",
    "postNATDestinationIPv6Address",
    "privateEnterpriseNumber",
    "App-ID",
    "User-ID"
]


csvDirectory = "/home/dwinkwor/nfcap/logs/csv"
    
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(('10.254.11.245', 2055))
readList = [server]

def fuzzCSVPath(nfHost, nfSourceID, subdir):

    sDir = csvDirectory + "/" + nfHost.replace(".","-") + "/" + str(nfSourceID) + "/" + subdir
    
    if not os.access(sDir, os.F_OK):
        os.makedirs(sDir)

    if os.access(sDir, os.F_OK|os.W_OK):
        return sDir

class nfHeader(ctypes.BigEndianStructure):
    _fields_ = [
        ("version", ctypes.c_uint16),
        ("count", ctypes.c_uint16),
    ]

class nf9Header(ctypes.BigEndianStructure):
    _fields_ = [
        ("sysUpTime", ctypes.c_uint32),
        ("unixSeconds", ctypes.c_uint32),
        ("sequenceNumber", ctypes.c_uint32),
        ("sourceID", ctypes.c_uint32)
    ]
    
class flowSet(ctypes.BigEndianStructure):
    _fields_ = [
        ("ID", ctypes.c_uint16),
        ("length", ctypes.c_uint16)]

class template(ctypes.BigEndianStructure):
    _fields_ = [
        ("ID", ctypes.c_uint16),
        ("fieldCount", ctypes.c_uint16)
    ]

class fieldSpec(ctypes.BigEndianStructure):
    _fields_ = [
        ("fieldType", ctypes.c_uint16),
        ("fieldLength", ctypes.c_uint16)
    ]

    
class nf9observationDomain(object):
    domainRegistry = {}

    def __init__(self,domain):
        self.domainID = domain
        nf9observationDomain.domainRegistry[domain] = self
        self.templates = {}
        self.templateFile = {"timeStamp": 0, "name": ""}
        self.dFileStamp = 0
        self.dFileName = ""
        self.lastTimeStamp = None
        

        
        
    def logFlows(self, templateList = [], flowList = []):
    
        modeParam = os.F_OK | os.R_OK
        

        if templateList:
            nfHost = templateList[0]["nfHost"]
            nfSourceID = templateList[0]["nfSourceID"]
            timeReceived = templateList[0]["timeReceived"]
            tPath = fuzzCSVPath(nfHost, nfSourceID, "templates")
            newFile = False
            if tPath:
                if timeReceived - self.templateFile["timeStamp"] > fileWindow:               
                    self.templateFile["timeStamp"] = timeReceived
                    self.templateFile["name"] = str(timeReceived) + ".csv"
                    newFile = True
                
                with open(tPath + "/" + self.templateFile["name"], 'a+') as csvfile:

                    twriter = csv.DictWriter(csvfile, delimiter=";", fieldnames=templateList[0].keys())
                    if newFile:
                        twriter.writeheader()
                        newFile = False
                    twriter.writerows(templateList)
                        
        if flowList:
            nfHost = flowList[0][1]
            nfSourceID = flowList[0][2]
            timeReceived = flowList[0][0]
            tPath = fuzzCSVPath(nfHost, nfSourceID, "dataFlows")
            newFile = False
            if tPath:
                if timeReceived - self.dFileStamp > fileWindow:               
                    self.dFileStamp = timeReceived
                    self.dFileName = str(int(timeReceived)) + ".csv"
                    newFile = True
                
                with open(tPath + "/" + self.dFileName, 'a+') as csvfile:

                    twriter = csv.writer(csvfile, delimiter=";")
                    if newFile:
                        twriter.writerow(dfnames)
                        newFile = False
                    twriter.writerows(flowList)
                            
                    
    def parseTemplate(self, data, offset):
        
        y = template.from_buffer(data, offset)
       

        self.templates[y.ID] = {}
        self.templates[y.ID]["struct"] = None
        self.templates[y.ID]["spec"] = []
        self.templates[y.ID]["yaml"] = None
        
        offset += 4
        fieldList = []
        fieldSpecList = []
        dFields = collections.OrderedDict()
        dFields[y.ID] = collections.OrderedDict()
        
        for x in xrange(1, y.fieldCount + 1):
            z = fieldSpec.from_buffer(data, offset)
            m = nfTypes.metaIE.registry[z.fieldType](z.fieldLength)
            dFields[y.ID]["Field" + str(x)]= collections.OrderedDict([("elementID", z.fieldType), ("name", m.nf9name), ("length", z.fieldLength)])
            fieldSpecList.append(m)
            fieldList.append((m.nf9name, m.seeType))
            offset += 4
        
        newdump = hiyapyco.dump(dFields)
        
        if y.ID in self.templates:
            if newdump == self.templates[y.ID]["yaml"]:
                return

        self.templates[y.ID]["struct"] = type(str(y.ID), (ctypes.BigEndianStructure,), {"_pack_": 1, "_fields_": fieldList})
        self.templates[y.ID]["spec"] = fieldSpecList
        self.templates[y.ID]["yaml"] = newdump
        
        return y.ID
        
    def parseData(self, data, offset, fSetID, flowEntry):
        
        y = self.templates[fSetID]["struct"].from_buffer(data, offset)

        for i in self.templates[fSetID]["spec"]:
            flowEntry[fieldIndex[i.nf9name]] = i.getPyVal(y.__getattribute__(i.nf9name))
        
  
        
    def parseNew(self, data, header, count):
        offset = 20
        flowList = []
        templateList = []
        timeReceived = time.time()
        for x in xrange(1, count + 1):
            y = flowSet.from_buffer(data, offset)
            if y.ID == 0:
                updatedID = self.parseTemplate(data, offset + 4)
                if updatedID:
                    templateEntry = collections.OrderedDict()
                    templateEntry["timeReceived"] = timeReceived
                    templateEntry["nfHost"] = self.domainID[0]
                    templateEntry["nfSourceID"] = self.domainID[1]
                    templateEntry["sysUpTime"] = header.sysUpTime
                    templateEntry["unixSeconds"] = header.unixSeconds
                    templateEntry["sequenceNumber"] = header.sequenceNumber
                    templateEntry["templateID"] = updatedID
                    templateEntry["fields"] = self.templates[updatedID]["yaml"]
                    templateList.append(templateEntry)
            elif y.ID > 255 and y.ID in self.templates:
                flowEntry = [None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None]
                flowEntry[0] = timeReceived
                flowEntry[1] = self.domainID[0]
                flowEntry[2] = self.domainID[1]
                flowEntry[3] = header.sysUpTime
                flowEntry[4] = header.unixSeconds
                flowEntry[5] = header.sequenceNumber
                flowEntry[6] = y.ID
                self.parseData(data, offset + 4, y.ID, flowEntry)
                flowList.append(flowEntry)
            offset += y.length
        
        self.logFlows(templateList, flowList)
      
running = 1

while running:
    inputReady, outputReady, exceptReady = select.select(readList, [], [])
    
    for item in inputReady:
        
        data = bytearray(8192)
        nbytes, addr = item.recvfrom_into(data)
        if data:
            xhead = nfHeader.from_buffer(data)
            if xhead.version == 9:
                yhead = nf9Header.from_buffer(data,4)
                domain = (addr[0], yhead.sourceID)
                if domain not in nf9observationDomain.domainRegistry:
                    nf9observationDomain.domainRegistry[domain] = nf9observationDomain(domain)
                
                nf9observationDomain.domainRegistry[domain].parseNew(data, yhead, xhead.count)
                

                
                 
    
            
    

    