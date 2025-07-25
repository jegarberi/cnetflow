from enum import IntEnum
from typing import List, Dict


class IPFIXFieldType(IntEnum):
    OCTETDELTACOUNT = 1
    PACKETDELTACOUNT = 2
    FLOWS = 3
    PROTOCOLIDENTIFIER = 4
    IPCLASSOFSERVICE = 5
    TCPCONTROLBITS = 6
    SOURCETRANSPORTPORT = 7
    SOURCEIPV4ADDRESS = 8
    SOURCEIPV4PREFIXLENGTH = 9
    INGRESSINTERFACE = 10
    DESTINATIONTRANSPORTPORT = 11
    DESTINATIONIPV4ADDRESS = 12
    DESTINATIONIPV4PREFIXLENGTH = 13
    EGRESSINTERFACE = 14
    IPNEXTHOPIPV4ADDRESS = 15
    BGPSOURCEASNUMBER = 16
    BGPDESTINATIONASNUMBER = 17
    BGPNEXTHOPIPV4ADDRESS = 18
    POSTMCASTPACKETDELTACOUNT = 19
    POSTMCASTOCTETDELTACOUNT = 20
    FLOWENDSYSUPTIME = 21
    FLOWSTARTSYSUPTIME = 22
    POSTOCTETDELTACOUNT = 23
    POSTPACKETDELTACOUNT = 24
    MINIMUMIPTOTALLENGTH = 25
    MAXIMUMIPTOTALLENGTH = 26
    SOURCEIPV6ADDRESS = 27
    DESTINATIONIPV6ADDRESS = 28
    SOURCEIPV6PREFIXLENGTH = 29
    DESTINATIONIPV6PREFIXLENGTH = 30
    FLOWLABELIPV6 = 31
    ICMPTYPECODEIPV4 = 32
    IGMPTYPE = 33
    SAMPLING_INTERVAL = 34
    SAMPLING_ALGORITHM = 35
    FLOWACTIVETIMEOUT = 36
    FLOWIDLETIMEOUT = 37
    ENGINE_TYPE = 38
    ENGINE_ID = 39
    EXPORTEDOCTETTOTALCOUNT = 40
    EXPORTEDMESSAGETOTALCOUNT = 41
    EXPORTEDFLOWRECORDTOTALCOUNT = 42
    SOURCEIPV4PREFIX = 44
    DESTINATIONIPV4PREFIX = 45
    MPLSTOPLABELTYPE = 46
    MPLSTOPLABELIPV4ADDRESS = 47
    FLOW_SAMPLER_ID = 48
    FLOW_SAMPLER_MODE = 49
    FLOW_SAMPLER_RANDOM_INTERVAL = 50
    VENDOR_PROPIETARY = 51
    MINIMUMTTL = 52
    MAXIMUMTTL = 53
    FRAGMENTIDENTIFICATION = 54
    POSTIPCLASSOFSERVICE = 55
    SOURCEMACADDRESS = 56
    POSTDESTINATIONMACADDRESS = 57
    VLANID = 58
    POSTVLANID = 59
    IPVERSION = 60
    FLOWDIRECTION = 61
    IPNEXTHOPIPV6ADDRESS = 62
    BGPNEXTHOPIPV6ADDRESS = 63
    IPV6EXTENSIONHEADERS = 64
    MPLSTOPLABELSTACKSECTION = 70
    MPLSLABELSTACKSECTION2 = 71
    MPLSLABELSTACKSECTION3 = 72
    MPLSLABELSTACKSECTION4 = 73
    MPLSLABELSTACKSECTION5 = 74
    MPLSLABELSTACKSECTION6 = 75
    MPLSLABELSTACKSECTION7 = 76
    MPLSLABELSTACKSECTION8 = 77
    MPLSLABELSTACKSECTION9 = 78
    MPLSLABELSTACKSECTION10 = 79
    DESTINATIONMACADDRESS = 80
    POSTSOURCEMACADDRESS = 81
    OCTETTOTALCOUNT = 85
    PACKETTOTALCOUNT = 86
    FRAGMENTOFFSET = 88
    MPLSVPNROUTEDISTINGUISHER = 90
    BGPNEXTADJACENTASNUMBER = 128
    BGPPREVADJACENTASNUMBER = 129
    EXPORTERIPV4ADDRESS = 130
    EXPORTERIPV6ADDRESS = 131
    DROPPEDOCTETDELTACOUNT = 132
    DROPPEDPACKETDELTACOUNT = 133
    DROPPEDOCTETTOTALCOUNT = 134
    DROPPEDPACKETTOTALCOUNT = 135
    FLOWENDREASON = 136
    COMMONPROPERTIESID = 137
    OBSERVATIONPOINTID = 138
    ICMPTYPECODEIPV6 = 139
    MPLSTOPLABELIPV6ADDRESS = 140
    LINECARDID = 141
    PORTID = 142
    METERINGPROCESSID = 143
    EXPORTINGPROCESSID = 144
    TEMPLATEID = 145
    WLANCHANNELID = 146
    WLANSSID = 147
    FLOWID = 148
    OBSERVATIONDOMAINID = 149
    FLOWSTARTSECONDS = 150
    FLOWENDSECONDS = 151
    FLOWSTARTMILLISECONDS = 152
    FLOWENDMILLISECONDS = 153
    FLOWSTARTMICROSECONDS = 154
    FLOWENDMICROSECONDS = 155
    FLOWSTARTNANOSECONDS = 156
    FLOWENDNANOSECONDS = 157
    FLOWSTARTDELTAMICROSECONDS = 158
    FLOWENDDELTAMICROSECONDS = 159
    SYSTEMINITTIMEMILLISECONDS = 160
    FLOWDURATIONMILLISECONDS = 161
    FLOWDURATIONMICROSECONDS = 162
    OBSERVEDFLOWTOTALCOUNT = 163
    IGNOREDPACKETTOTALCOUNT = 164
    IGNOREDOCTETTOTALCOUNT = 165
    NOTSENTFLOWTOTALCOUNT = 166
    NOTSENTPACKETTOTALCOUNT = 167
    NOTSENTOCTETTOTALCOUNT = 168
    DESTINATIONIPV6PREFIX = 169
    SOURCEIPV6PREFIX = 170
    POSTOCTETTOTALCOUNT = 171
    POSTPACKETTOTALCOUNT = 172
    FLOWKEYINDICATOR = 173
    POSTMCASTPACKETTOTALCOUNT = 174
    POSTMCASTOCTETTOTALCOUNT = 175
    ICMPTYPEIPV4 = 176
    ICMPCODEIPV4 = 177
    ICMPTYPEIPV6 = 178
    ICMPCODEIPV6 = 179
    UDPSOURCEPORT = 180
    UDPDESTINATIONPORT = 181
    TCPSOURCEPORT = 182
    TCPDESTINATIONPORT = 183
    TCPSEQUENCENUMBER = 184
    TCPACKNOWLEDGEMENTNUMBER = 185
    TCPWINDOWSIZE = 186
    TCPURGENTPOINTER = 187
    TCPHEADERLENGTH = 188
    IPHEADERLENGTH = 189
    TOTALLENGTHIPV4 = 190
    PAYLOADLENGTHIPV6 = 191
    IPTTL = 192
    NEXTHEADERIPV6 = 193
    MPLSPAYLOADLENGTH = 194
    IPDIFFSERVCODEPOINT = 195
    IPPRECEDENCE = 196
    FRAGMENTFLAGS = 197
    OCTETDELTASUMOFSQUARES = 198
    OCTETTOTALSUMOFSQUARES = 199
    MPLSTOPLABELTTL = 200
    MPLSLABELSTACKLENGTH = 201
    MPLSLABELSTACKDEPTH = 202
    MPLSTOPLABELEXP = 203
    IPPAYLOADLENGTH = 204
    UDPMESSAGELENGTH = 205
    ISMULTICAST = 206
    IPV4IHL = 207
    IPV4OPTIONS = 208
    TCPOPTIONS = 209
    PADDINGOCTETS = 210
    COLLECTORIPV4ADDRESS = 211
    COLLECTORIPV6ADDRESS = 212
    COLLECTORINTERFACE = 213
    COLLECTORPROTOCOLVERSION = 214
    COLLECTORTRANSPORTPROTOCOL = 215
    COLLECTORTRANSPORTPORT = 216
    EXPORTERTRANSPORTPORT = 217
    TCPSYNTOTALCOUNT = 218
    TCPFINTOTALCOUNT = 219
    TCPRSTTOTALCOUNT = 220
    TCPPSHTOTALCOUNT = 221
    TCPACKTOTALCOUNT = 222
    TCPURGTOTALCOUNT = 223
    IPTOTALLENGTH = 224
    POSTNATSOURCEIPV4ADDRESS = 225
    POSTNATDESTINATIONIPV4ADDRESS = 226
    POSTNATSOURCETRANSPORTPORT = 227
    POSTNATDESTINATIONTRANSPORTPORT = 228
    NATEVENTTYPE = 230
    POSTMPLSTOPLABELEXP = 237
    TCPWINDOWSCALE = 238
    BIFLOWDIRECTION = 239
    OBSERVATIONPOINTID_PSAMP = 300
    SELECTIONSEQUENCEID = 301
    SELECTORID = 302
    INFORMATIONELEMENTID = 303
    SELECTORALGORITHM = 304
    SAMPLINGPACKETINTERVAL = 305
    SAMPLINGPACKETSPACE = 306
    SAMPLINGTIMEINTERVAL = 307
    SAMPLINGTIMESPACE = 308
    SAMPLINGSIZE = 309
    SAMPLINGPOPULATION = 310
    SAMPLINGPROBABILITY = 311
    DATALINKFRAMESIZE = 312
    IPHEADERPACKETSECTION = 313
    IPPAYLOADPACKETSECTION = 314
    DATALINKFRAMESECTION = 315
    MPLSLABELSTACKSECTION = 316
    MPLSPAYLOADPACKETSECTION = 317
    PACKETSOBSERVED = 318
    PACKETSSELECTED = 319
    FIXEDERROR = 320
    RELATIVEERROR = 321
    OBSERVATIONTIMESECONDS = 322
    OBSERVATIONTIMEMILLISECONDS = 323
    OBSERVATIONTIMEMICROSECONDS = 324
    OBSERVATIONTIMENANOSECONDS = 325
    DIGESTHASHVALUE = 326
    HASHIPPAYLOADOFFSET = 327
    HASHIPPAYLOADSIZE = 328
    HASHOUTPUTRANGEMIN = 329
    HASHOUTPUTRANGEMAX = 330
    HASHSELECTEDRANGEMIN = 331
    HASHSELECTEDRANGEMAX = 332
    HASHDIGESTOUTPUT = 333
    HASHINITIALISERVALUE = 334


# Fragment of the ipfix_field_types array extracted from the file (manually copied or parsed)
# For this example, we will only demonstrate a small portion. In practice, you would parse the entire file.
original_entries = [
    [0, 0, 0, "IPFIX_CODING_UINT", "none", ""],
    [0, IPFIXFieldType.OCTETDELTACOUNT, 8, "IPFIX_CODING_UINT", "octetDeltaCount", ""],
    [0, IPFIXFieldType.PACKETDELTACOUNT, 8, "IPFIX_CODING_UINT", "packetDeltaCount", ""],
    [0, IPFIXFieldType.FLOWS, 8, "IPFIX_CODING_UINT", "flows", "Netflow Number of Flows that were aggregated"],
    [0, IPFIXFieldType.PROTOCOLIDENTIFIER, 1, "IPFIX_CODING_UINT", "protocolIdentifier", ""],
    [0, IPFIXFieldType.IPCLASSOFSERVICE, 1, "IPFIX_CODING_UINT", "ipClassOfService", ""],
    [0, IPFIXFieldType.TCPCONTROLBITS, 1, "IPFIX_CODING_UINT", "tcpControlBits", ""],
    [0, IPFIXFieldType.SOURCETRANSPORTPORT, 2, "IPFIX_CODING_UINT", "sourceTransportPort", ""],
    [0, IPFIXFieldType.SOURCEIPV4ADDRESS, 4, "IPFIX_CODING_IPADDR", "sourceIPv4Address", ""],
    [0, IPFIXFieldType.SOURCEIPV4PREFIXLENGTH, 1, "IPFIX_CODING_UINT", "sourceIPv4PrefixLength", ""],
    [0, IPFIXFieldType.INGRESSINTERFACE, 4, "IPFIX_CODING_UINT", "ingressInterface", ""],
    [0, IPFIXFieldType.DESTINATIONTRANSPORTPORT, 2, "IPFIX_CODING_UINT", "destinationTransportPort", ""],
    [0, IPFIXFieldType.DESTINATIONIPV4ADDRESS, 4, "IPFIX_CODING_IPADDR", "destinationIPv4Address", ""],
    [0, IPFIXFieldType.DESTINATIONIPV4PREFIXLENGTH, 1, "IPFIX_CODING_UINT", "destinationIPv4PrefixLength", ""],
    [0, IPFIXFieldType.EGRESSINTERFACE, 4, "IPFIX_CODING_UINT", "egressInterface", ""],
    [0, IPFIXFieldType.IPNEXTHOPIPV4ADDRESS, 4, "IPFIX_CODING_IPADDR", "ipNextHopIPv4Address", ""],
    [0, IPFIXFieldType.BGPSOURCEASNUMBER, 4, "IPFIX_CODING_UINT", "bgpSourceAsNumber", ""],
    [0, IPFIXFieldType.BGPDESTINATIONASNUMBER, 4, "IPFIX_CODING_UINT", "bgpDestinationAsNumber", ""],
    [0, IPFIXFieldType.BGPNEXTHOPIPV4ADDRESS, 4, "IPFIX_CODING_IPADDR", "bgpNextHopIPv4Address", ""],
    [0, IPFIXFieldType.POSTMCASTPACKETDELTACOUNT, 8, "IPFIX_CODING_UINT", "postMCastPacketDeltaCount", ""],
    [0, IPFIXFieldType.POSTMCASTOCTETDELTACOUNT, 8, "IPFIX_CODING_UINT", "postMCastOctetDeltaCount", ""],
    [0, IPFIXFieldType.FLOWENDSYSUPTIME, 4, "IPFIX_CODING_UINT", "flowEndSysUpTime", ""],
    [0, IPFIXFieldType.FLOWSTARTSYSUPTIME, 4, "IPFIX_CODING_UINT", "flowStartSysUpTime", ""],
    [0, IPFIXFieldType.POSTOCTETDELTACOUNT, 8, "IPFIX_CODING_UINT", "postOctetDeltaCount", ""],
    [0, IPFIXFieldType.POSTPACKETDELTACOUNT, 8, "IPFIX_CODING_UINT", "postPacketDeltaCount", ""],
    [0, IPFIXFieldType.MINIMUMIPTOTALLENGTH, 8, "IPFIX_CODING_UINT", "minimumIpTotalLength", ""],
    [0, IPFIXFieldType.MAXIMUMIPTOTALLENGTH, 8, "IPFIX_CODING_UINT", "maximumIpTotalLength", ""],
    [0, IPFIXFieldType.SOURCEIPV6ADDRESS, 16, "IPFIX_CODING_IPADDR", "sourceIPv6Address", ""],
    [0, IPFIXFieldType.DESTINATIONIPV6ADDRESS, 16, "IPFIX_CODING_IPADDR", "destinationIPv6Address", ""],
    [0, IPFIXFieldType.SOURCEIPV6PREFIXLENGTH, 1, "IPFIX_CODING_UINT", "sourceIPv6PrefixLength", ""],
    [0, IPFIXFieldType.DESTINATIONIPV6PREFIXLENGTH, 1, "IPFIX_CODING_UINT", "destinationIPv6PrefixLength", ""],
    [0, IPFIXFieldType.FLOWLABELIPV6, 4, "IPFIX_CODING_UINT", "flowLabelIPv6", ""],
    [0, IPFIXFieldType.ICMPTYPECODEIPV4, 2, "IPFIX_CODING_UINT", "icmpTypeCodeIPv4", ""],
    [0, IPFIXFieldType.IGMPTYPE, 1, "IPFIX_CODING_UINT", "igmpType", ""],
    [0, IPFIXFieldType.SAMPLING_INTERVAL, 4, "IPFIX_CODING_UINT", "sampling_interval", "Netflow Sampling Interval"],
    [0, IPFIXFieldType.SAMPLING_ALGORITHM, 1, "IPFIX_CODING_UINT", "sampling_algorithm", "Netflow Sampling Algorithm"],
    [0, IPFIXFieldType.FLOWACTIVETIMEOUT, 2, "IPFIX_CODING_UINT", "flowActiveTimeout", ""],
    [0, IPFIXFieldType.FLOWIDLETIMEOUT, 2, "IPFIX_CODING_UINT", "flowIdleTimeout", ""],
    [0, IPFIXFieldType.ENGINE_TYPE, 1, "IPFIX_CODING_UINT", "engine_type", "Netflow Engine Type"],
    [0, IPFIXFieldType.ENGINE_ID, 1, "IPFIX_CODING_UINT", "engine_id", "Netflow Engine ID"],
    [0, IPFIXFieldType.EXPORTEDOCTETTOTALCOUNT, 8, "IPFIX_CODING_UINT", "exportedOctetTotalCount", ""],
    [0, IPFIXFieldType.EXPORTEDMESSAGETOTALCOUNT, 8, "IPFIX_CODING_UINT", "exportedMessageTotalCount", ""],
    [0, IPFIXFieldType.EXPORTEDFLOWRECORDTOTALCOUNT, 8, "IPFIX_CODING_UINT", "exportedFlowRecordTotalCount", ""],
    [0, IPFIXFieldType.SOURCEIPV4PREFIX, 4, "IPFIX_CODING_IPADDR", "sourceIPv4Prefix", ""],
    [0, IPFIXFieldType.DESTINATIONIPV4PREFIX, 4, "IPFIX_CODING_IPADDR", "destinationIPv4Prefix", ""],
    [0, IPFIXFieldType.MPLSTOPLABELTYPE, 1, "IPFIX_CODING_UINT", "mplsTopLabelType", ""],
    [0, IPFIXFieldType.MPLSTOPLABELIPV4ADDRESS, 4, "IPFIX_CODING_IPADDR", "mplsTopLabelIPv4Address", ""],
    [0, IPFIXFieldType.FLOW_SAMPLER_ID, 1, "IPFIX_CODING_UINT", "flow_sampler_id", "Netflow Flow Sampler ID"],
    [0, IPFIXFieldType.FLOW_SAMPLER_MODE, 1, "IPFIX_CODING_UINT", "flow_sampler_mode", "Netflow Flow Sampler Mode"],
    [0, IPFIXFieldType.FLOW_SAMPLER_RANDOM_INTERVAL, 4, "IPFIX_CODING_UINT", "flow_sampler_random_interval",
     "Netflow Packet Sample Interval"],
    [0, IPFIXFieldType.VENDOR_PROPIETARY, 4, "IPFIX_CODING_UINT", "*Vendor Proprietary*", ""],
    [0, IPFIXFieldType.MINIMUMTTL, 1, "IPFIX_CODING_UINT", "minimumTTL", ""],
    [0, IPFIXFieldType.MAXIMUMTTL, 1, "IPFIX_CODING_UINT", "maximumTTL", ""],
    [0, IPFIXFieldType.FRAGMENTIDENTIFICATION, 4, "IPFIX_CODING_UINT", "fragmentIdentification", ""],
    [0, IPFIXFieldType.POSTIPCLASSOFSERVICE, 1, "IPFIX_CODING_UINT", "postIpClassOfService", ""],
    [0, IPFIXFieldType.SOURCEMACADDRESS, 6, "IPFIX_CODING_BYTES", "sourceMacAddress", ""],
    [0, IPFIXFieldType.POSTDESTINATIONMACADDRESS, 6, "IPFIX_CODING_BYTES", "postDestinationMacAddress", ""],
    [0, IPFIXFieldType.VLANID, 2, "IPFIX_CODING_UINT", "vlanId", ""],
    [0, IPFIXFieldType.POSTVLANID, 2, "IPFIX_CODING_UINT", "postVlanId", ""],
    [0, IPFIXFieldType.IPVERSION, 1, "IPFIX_CODING_UINT", "ipVersion", ""],
    [0, IPFIXFieldType.FLOWDIRECTION, 1, "IPFIX_CODING_UINT", "flowDirection", ""],
    [0, IPFIXFieldType.IPNEXTHOPIPV6ADDRESS, 16, "IPFIX_CODING_IPADDR", "ipNextHopIPv6Address", ""],
    [0, IPFIXFieldType.BGPNEXTHOPIPV6ADDRESS, 16, "IPFIX_CODING_IPADDR", "bgpNextHopIPv6Address", ""],
    [0, IPFIXFieldType.IPV6EXTENSIONHEADERS, 4, "IPFIX_CODING_UINT", "ipv6ExtensionHeaders", ""],
    [0, IPFIXFieldType.MPLSTOPLABELSTACKSECTION, 65535, "IPFIX_CODING_BYTES", "mplsTopLabelStackSection", ""],
    [0, IPFIXFieldType.MPLSLABELSTACKSECTION2, 65535, "IPFIX_CODING_BYTES", "mplsLabelStackSection2", ""],
    [0, IPFIXFieldType.MPLSLABELSTACKSECTION3, 65535, "IPFIX_CODING_BYTES", "mplsLabelStackSection3", ""],
    [0, IPFIXFieldType.MPLSLABELSTACKSECTION4, 65535, "IPFIX_CODING_BYTES", "mplsLabelStackSection4", ""],
    [0, IPFIXFieldType.MPLSLABELSTACKSECTION5, 65535, "IPFIX_CODING_BYTES", "mplsLabelStackSection5", ""],
    [0, IPFIXFieldType.MPLSLABELSTACKSECTION6, 65535, "IPFIX_CODING_BYTES", "mplsLabelStackSection6", ""],
    [0, IPFIXFieldType.MPLSLABELSTACKSECTION7, 65535, "IPFIX_CODING_BYTES", "mplsLabelStackSection7", ""],
    [0, IPFIXFieldType.MPLSLABELSTACKSECTION8, 65535, "IPFIX_CODING_BYTES", "mplsLabelStackSection8", ""],
    [0, IPFIXFieldType.MPLSLABELSTACKSECTION9, 65535, "IPFIX_CODING_BYTES", "mplsLabelStackSection9", ""],
    [0, IPFIXFieldType.MPLSLABELSTACKSECTION10, 65535, "IPFIX_CODING_BYTES", "mplsLabelStackSection10", ""],
    [0, IPFIXFieldType.DESTINATIONMACADDRESS, 6, "IPFIX_CODING_BYTES", "destinationMacAddress", ""],
    [0, IPFIXFieldType.POSTSOURCEMACADDRESS, 6, "IPFIX_CODING_BYTES", "postSourceMacAddress", ""],
    [0, IPFIXFieldType.OCTETTOTALCOUNT, 8, "IPFIX_CODING_UINT", "octetTotalCount", ""],
    [0, IPFIXFieldType.PACKETTOTALCOUNT, 8, "IPFIX_CODING_UINT", "packetTotalCount", ""],
    [0, IPFIXFieldType.FRAGMENTOFFSET, 2, "IPFIX_CODING_UINT", "fragmentOffset", ""],
    [0, IPFIXFieldType.MPLSVPNROUTEDISTINGUISHER, 65535, "IPFIX_CODING_BYTES", "mplsVpnRouteDistinguisher", ""],
    [0, IPFIXFieldType.BGPNEXTADJACENTASNUMBER, 4, "IPFIX_CODING_UINT", "bgpNextAdjacentAsNumber", ""],
    [0, IPFIXFieldType.BGPPREVADJACENTASNUMBER, 4, "IPFIX_CODING_UINT", "bgpPrevAdjacentAsNumber", ""],
    [0, IPFIXFieldType.EXPORTERIPV4ADDRESS, 4, "IPFIX_CODING_IPADDR", "exporterIPv4Address", ""],
    [0, IPFIXFieldType.EXPORTERIPV6ADDRESS, 16, "IPFIX_CODING_IPADDR", "exporterIPv6Address", ""],
    [0, IPFIXFieldType.DROPPEDOCTETDELTACOUNT, 8, "IPFIX_CODING_UINT", "droppedOctetDeltaCount", ""],
    [0, IPFIXFieldType.DROPPEDPACKETDELTACOUNT, 8, "IPFIX_CODING_UINT", "droppedPacketDeltaCount", ""],
    [0, IPFIXFieldType.DROPPEDOCTETTOTALCOUNT, 8, "IPFIX_CODING_UINT", "droppedOctetTotalCount", ""],
    [0, IPFIXFieldType.DROPPEDPACKETTOTALCOUNT, 8, "IPFIX_CODING_UINT", "droppedPacketTotalCount", ""],
    [0, IPFIXFieldType.FLOWENDREASON, 1, "IPFIX_CODING_UINT", "flowEndReason", ""],
    [0, IPFIXFieldType.COMMONPROPERTIESID, 8, "IPFIX_CODING_UINT", "commonPropertiesId", ""],
    [0, IPFIXFieldType.OBSERVATIONPOINTID, 4, "IPFIX_CODING_UINT", "observationPointId", ""],
    [0, IPFIXFieldType.ICMPTYPECODEIPV6, 2, "IPFIX_CODING_UINT", "icmpTypeCodeIPv6", ""],
    [0, IPFIXFieldType.MPLSTOPLABELIPV6ADDRESS, 16, "IPFIX_CODING_IPADDR", "mplsTopLabelIPv6Address", ""],
    [0, IPFIXFieldType.LINECARDID, 4, "IPFIX_CODING_UINT", "lineCardId", ""],
    [0, IPFIXFieldType.PORTID, 4, "IPFIX_CODING_UINT", "portId", ""],
    [0, IPFIXFieldType.METERINGPROCESSID, 4, "IPFIX_CODING_UINT", "meteringProcessId", ""],
    [0, IPFIXFieldType.EXPORTINGPROCESSID, 4, "IPFIX_CODING_UINT", "exportingProcessId", ""],
    [0, IPFIXFieldType.TEMPLATEID, 2, "IPFIX_CODING_UINT", "templateId", ""],
    [0, IPFIXFieldType.WLANCHANNELID, 1, "IPFIX_CODING_UINT", "wlanChannelId", ""],
    [0, IPFIXFieldType.WLANSSID, 65535, "IPFIX_CODING_STRING", "wlanSSID", ""],
    [0, IPFIXFieldType.FLOWID, 8, "IPFIX_CODING_UINT", "flowId", ""],
    [0, IPFIXFieldType.OBSERVATIONDOMAINID, 4, "IPFIX_CODING_UINT", "observationDomainId", ""],
    [0, IPFIXFieldType.FLOWSTARTSECONDS, 4, "IPFIX_CODING_UINT", "flowStartSeconds", ""],
    [0, IPFIXFieldType.FLOWENDSECONDS, 4, "IPFIX_CODING_UINT", "flowEndSeconds", ""],
    [0, IPFIXFieldType.FLOWSTARTMILLISECONDS, 8, "IPFIX_CODING_UINT", "flowStartMilliseconds", ""],
    [0, IPFIXFieldType.FLOWENDMILLISECONDS, 8, "IPFIX_CODING_UINT", "flowEndMilliseconds", ""],
    [0, IPFIXFieldType.FLOWSTARTMICROSECONDS, 8, "IPFIX_CODING_NTP", "flowStartMicroseconds", ""],
    [0, IPFIXFieldType.FLOWENDMICROSECONDS, 8, "IPFIX_CODING_NTP", "flowEndMicroseconds", ""],
    [0, IPFIXFieldType.FLOWSTARTNANOSECONDS, 8, "IPFIX_CODING_NTP", "flowStartNanoseconds", ""],
    [0, IPFIXFieldType.FLOWENDNANOSECONDS, 8, "IPFIX_CODING_NTP", "flowEndNanoseconds", ""],
    [0, IPFIXFieldType.FLOWSTARTDELTAMICROSECONDS, 4, "IPFIX_CODING_UINT", "flowStartDeltaMicroseconds", ""],
    [0, IPFIXFieldType.FLOWENDDELTAMICROSECONDS, 4, "IPFIX_CODING_UINT", "flowEndDeltaMicroseconds", ""],
    [0, IPFIXFieldType.SYSTEMINITTIMEMILLISECONDS, 8, "IPFIX_CODING_UINT", "systemInitTimeMilliseconds", ""],
    [0, IPFIXFieldType.FLOWDURATIONMILLISECONDS, 4, "IPFIX_CODING_UINT", "flowDurationMilliseconds", ""],
    [0, IPFIXFieldType.FLOWDURATIONMICROSECONDS, 4, "IPFIX_CODING_UINT", "flowDurationMicroseconds", ""],
    [0, IPFIXFieldType.OBSERVEDFLOWTOTALCOUNT, 8, "IPFIX_CODING_UINT", "observedFlowTotalCount", ""],
    [0, IPFIXFieldType.IGNOREDPACKETTOTALCOUNT, 8, "IPFIX_CODING_UINT", "ignoredPacketTotalCount", ""],
    [0, IPFIXFieldType.IGNOREDOCTETTOTALCOUNT, 8, "IPFIX_CODING_UINT", "ignoredOctetTotalCount", ""],
    [0, IPFIXFieldType.NOTSENTFLOWTOTALCOUNT, 8, "IPFIX_CODING_UINT", "notSentFlowTotalCount", ""],
    [0, IPFIXFieldType.NOTSENTPACKETTOTALCOUNT, 8, "IPFIX_CODING_UINT", "notSentPacketTotalCount", ""],
    [0, IPFIXFieldType.NOTSENTOCTETTOTALCOUNT, 8, "IPFIX_CODING_UINT", "notSentOctetTotalCount", ""],
    [0, IPFIXFieldType.DESTINATIONIPV6PREFIX, 16, "IPFIX_CODING_IPADDR", "destinationIPv6Prefix", ""],
    [0, IPFIXFieldType.SOURCEIPV6PREFIX, 16, "IPFIX_CODING_IPADDR", "sourceIPv6Prefix", ""],
    [0, IPFIXFieldType.POSTOCTETTOTALCOUNT, 8, "IPFIX_CODING_UINT", "postOctetTotalCount", ""],
    [0, IPFIXFieldType.POSTPACKETTOTALCOUNT, 8, "IPFIX_CODING_UINT", "postPacketTotalCount", ""],
    [0, IPFIXFieldType.FLOWKEYINDICATOR, 8, "IPFIX_CODING_UINT", "flowKeyIndicator", ""],
    [0, IPFIXFieldType.POSTMCASTPACKETTOTALCOUNT, 8, "IPFIX_CODING_UINT", "postMCastPacketTotalCount", ""],
    [0, IPFIXFieldType.POSTMCASTOCTETTOTALCOUNT, 8, "IPFIX_CODING_UINT", "postMCastOctetTotalCount", ""],
    [0, IPFIXFieldType.ICMPTYPEIPV4, 1, "IPFIX_CODING_UINT", "icmpTypeIPv4", ""],
    [0, IPFIXFieldType.ICMPCODEIPV4, 1, "IPFIX_CODING_UINT", "icmpCodeIPv4", ""],
    [0, IPFIXFieldType.ICMPTYPEIPV6, 1, "IPFIX_CODING_UINT", "icmpTypeIPv6", ""],  # Fixed the c1 error
    [0, IPFIXFieldType.ICMPCODEIPV6, 1, "IPFIX_CODING_UINT", "icmpCodeIPv6", ""],
    [0, IPFIXFieldType.UDPSOURCEPORT, 2, "IPFIX_CODING_UINT", "udpSourcePort", ""],
    [0, IPFIXFieldType.UDPDESTINATIONPORT, 2, "IPFIX_CODING_UINT", "udpDestinationPort", ""],
    [0, IPFIXFieldType.TCPSOURCEPORT, 2, "IPFIX_CODING_UINT", "tcpSourcePort", ""],
    [0, IPFIXFieldType.TCPDESTINATIONPORT, 2, "IPFIX_CODING_UINT", "tcpDestinationPort", ""],
    [0, IPFIXFieldType.TCPSEQUENCENUMBER, 4, "IPFIX_CODING_UINT", "tcpSequenceNumber", ""],
    [0, IPFIXFieldType.TCPACKNOWLEDGEMENTNUMBER, 4, "IPFIX_CODING_UINT", "tcpAcknowledgementNumber", ""],
    [0, IPFIXFieldType.TCPWINDOWSIZE, 2, "IPFIX_CODING_UINT", "tcpWindowSize", ""],
    [0, IPFIXFieldType.TCPURGENTPOINTER, 2, "IPFIX_CODING_UINT", "tcpUrgentPointer", ""],
    [0, IPFIXFieldType.TCPHEADERLENGTH, 1, "IPFIX_CODING_UINT", "tcpHeaderLength", ""],
    [0, IPFIXFieldType.IPHEADERLENGTH, 1, "IPFIX_CODING_UINT", "ipHeaderLength", ""],
    [0, IPFIXFieldType.TOTALLENGTHIPV4, 2, "IPFIX_CODING_UINT", "totalLengthIPv4", ""],
    [0, IPFIXFieldType.PAYLOADLENGTHIPV6, 2, "IPFIX_CODING_UINT", "payloadLengthIPv6", ""],
    [0, IPFIXFieldType.IPTTL, 1, "IPFIX_CODING_UINT", "ipTTL", ""],
    [0, IPFIXFieldType.NEXTHEADERIPV6, 1, "IPFIX_CODING_UINT", "nextHeaderIPv6", ""],
    [0, IPFIXFieldType.MPLSPAYLOADLENGTH, 4, "IPFIX_CODING_UINT", "mplsPayloadLength", ""],
    [0, IPFIXFieldType.IPDIFFSERVCODEPOINT, 1, "IPFIX_CODING_UINT", "ipDiffServCodePoint", ""],
    [0, IPFIXFieldType.IPPRECEDENCE, 1, "IPFIX_CODING_UINT", "ipPrecedence", ""],
    [0, IPFIXFieldType.FRAGMENTFLAGS, 1, "IPFIX_CODING_UINT", "fragmentFlags", ""],
    [0, IPFIXFieldType.OCTETDELTASUMOFSQUARES, 8, "IPFIX_CODING_UINT", "octetDeltaSumOfSquares", ""],
    [0, IPFIXFieldType.OCTETTOTALSUMOFSQUARES, 8, "IPFIX_CODING_UINT", "octetTotalSumOfSquares", ""],
    [0, IPFIXFieldType.MPLSTOPLABELTTL, 1, "IPFIX_CODING_UINT", "mplsTopLabelTTL", ""],
    [0, IPFIXFieldType.MPLSLABELSTACKLENGTH, 4, "IPFIX_CODING_UINT", "mplsLabelStackLength", ""],
    [0, IPFIXFieldType.MPLSLABELSTACKDEPTH, 4, "IPFIX_CODING_UINT", "mplsLabelStackDepth", ""],
    [0, IPFIXFieldType.MPLSTOPLABELEXP, 1, "IPFIX_CODING_UINT", "mplsTopLabelExp", ""],
    [0, IPFIXFieldType.IPPAYLOADLENGTH, 4, "IPFIX_CODING_UINT", "ipPayloadLength", ""],
    [0, IPFIXFieldType.UDPMESSAGELENGTH, 2, "IPFIX_CODING_UINT", "udpMessageLength", ""],
    [0, IPFIXFieldType.ISMULTICAST, 1, "IPFIX_CODING_UINT", "isMulticast", ""],
    [0, IPFIXFieldType.IPV4IHL, 1, "IPFIX_CODING_UINT", "ipv4IHL", ""],
    [0, IPFIXFieldType.IPV4OPTIONS, 4, "IPFIX_CODING_UINT", "ipv4Options", ""],
    [0, IPFIXFieldType.TCPOPTIONS, 8, "IPFIX_CODING_UINT", "tcpOptions", ""],
    [0, IPFIXFieldType.PADDINGOCTETS, 65535, "IPFIX_CODING_BYTES", "paddingOctets", ""],
    [0, IPFIXFieldType.COLLECTORIPV4ADDRESS, 4, "IPFIX_CODING_IPADDR", "collectorIPv4Address", ""],
    [0, IPFIXFieldType.COLLECTORIPV6ADDRESS, 16, "IPFIX_CODING_IPADDR", "collectorIPv6Address", ""],
    [0, IPFIXFieldType.COLLECTORINTERFACE, 4, "IPFIX_CODING_UINT", "collectorInterface", ""],
    [0, IPFIXFieldType.COLLECTORPROTOCOLVERSION, 1, "IPFIX_CODING_UINT", "collectorProtocolVersion", ""],
    [0, IPFIXFieldType.COLLECTORTRANSPORTPROTOCOL, 1, "IPFIX_CODING_UINT", "collectorTransportProtocol", ""],
    [0, IPFIXFieldType.COLLECTORTRANSPORTPORT, 2, "IPFIX_CODING_UINT", "collectorTransportPort", ""],
    [0, IPFIXFieldType.EXPORTERTRANSPORTPORT, 2, "IPFIX_CODING_UINT", "exporterTransportPort", ""],
    [0, IPFIXFieldType.TCPSYNTOTALCOUNT, 8, "IPFIX_CODING_UINT", "tcpSynTotalCount", ""],
    [0, IPFIXFieldType.TCPFINTOTALCOUNT, 8, "IPFIX_CODING_UINT", "tcpFinTotalCount", ""],
    [0, IPFIXFieldType.TCPRSTTOTALCOUNT, 8, "IPFIX_CODING_UINT", "tcpRstTotalCount", ""],
    [0, IPFIXFieldType.TCPPSHTOTALCOUNT, 8, "IPFIX_CODING_UINT", "tcpPshTotalCount", ""],
    [0, IPFIXFieldType.TCPACKTOTALCOUNT, 8, "IPFIX_CODING_UINT", "tcpAckTotalCount", ""],
    [0, IPFIXFieldType.TCPURGTOTALCOUNT, 8, "IPFIX_CODING_UINT", "tcpUrgTotalCount", ""],
    [0, IPFIXFieldType.IPTOTALLENGTH, 8, "IPFIX_CODING_UINT", "ipTotalLength", ""],
    [0, IPFIXFieldType.POSTNATSOURCEIPV4ADDRESS, 4, "IPFIX_CODING_IPADDR", "post_nat_source_ipaddr", ""],
    [0, IPFIXFieldType.POSTNATDESTINATIONIPV4ADDRESS, 4, "IPFIX_CODING_IPADDR", "post_nat_destination_ipaddr", ""],
    [0, IPFIXFieldType.POSTNATSOURCETRANSPORTPORT, 4, "IPFIX_CODING_UINT", "post_nat_source_transport_port", ""],
    [0, IPFIXFieldType.POSTNATDESTINATIONTRANSPORTPORT, 4, "IPFIX_CODING_UINT", "post_nat_destination_transport_port",
     ""],
    [0, IPFIXFieldType.NATEVENTTYPE, 4, "IPFIX_CODING_UINT", "nat_event_type",
     ""],
    [0, IPFIXFieldType.POSTMPLSTOPLABELEXP, 1, "IPFIX_CODING_UINT", "postMplsTopLabelExp", ""],
    [0, IPFIXFieldType.TCPWINDOWSCALE, 2, "IPFIX_CODING_UINT", "tcpWindowScale", ""],

    [0, IPFIXFieldType.OBSERVATIONPOINTID_PSAMP, 8, "IPFIX_CODING_UINT", "observationPointId_PSAMP", ""],
    [0, IPFIXFieldType.SELECTIONSEQUENCEID, 8, "IPFIX_CODING_UINT", "selectionSequenceId", ""],
    [0, IPFIXFieldType.SELECTORID, 2, "IPFIX_CODING_UINT", "selectorId", ""],
    [0, IPFIXFieldType.INFORMATIONELEMENTID, 2, "IPFIX_CODING_UINT", "informationElementId", ""],
    [0, IPFIXFieldType.SELECTORALGORITHM, 2, "IPFIX_CODING_UINT", "selectorAlgorithm", ""],
    [0, IPFIXFieldType.SAMPLINGPACKETINTERVAL, 4, "IPFIX_CODING_UINT", "samplingPacketInterval", ""],
    [0, IPFIXFieldType.SAMPLINGPACKETSPACE, 4, "IPFIX_CODING_UINT", "samplingPacketSpace", ""],
    [0, IPFIXFieldType.SAMPLINGTIMEINTERVAL, 8, "IPFIX_CODING_NTP", "samplingTimeInterval", ""],
    [0, IPFIXFieldType.SAMPLINGTIMESPACE, 8, "IPFIX_CODING_NTP", "samplingTimeSpace", ""],
    [0, IPFIXFieldType.SAMPLINGSIZE, 4, "IPFIX_CODING_UINT", "samplingSize", ""],
    [0, IPFIXFieldType.SAMPLINGPOPULATION, 4, "IPFIX_CODING_UINT", "samplingPopulation", ""],
    [0, IPFIXFieldType.SAMPLINGPROBABILITY, 8, "IPFIX_CODING_FLOAT", "samplingProbability", ""],
    [0, IPFIXFieldType.DATALINKFRAMESIZE, 4, "IPFIX_CODING_UINT", "dataLinkFrameSize", ""],
    [0, IPFIXFieldType.IPHEADERPACKETSECTION, 65535, "IPFIX_CODING_BYTES", "ipHeaderPacketSection", ""],
    [0, IPFIXFieldType.IPPAYLOADPACKETSECTION, 65535, "IPFIX_CODING_BYTES", "ipPayloadPacketSection", ""],
    [0, IPFIXFieldType.DATALINKFRAMESECTION, 65535, "IPFIX_CODING_BYTES", "dataLinkFrameSection", ""],
    [0, IPFIXFieldType.MPLSLABELSTACKSECTION, 65535, "IPFIX_CODING_BYTES", "mplsLabelStackSection", ""],
    [0, IPFIXFieldType.MPLSPAYLOADPACKETSECTION, 65535, "IPFIX_CODING_BYTES", "mplsPayloadPacketSection", ""],
    [0, IPFIXFieldType.PACKETSOBSERVED, 8, "IPFIX_CODING_UINT", "packetsObserved", ""],
    [0, IPFIXFieldType.PACKETSSELECTED, 8, "IPFIX_CODING_UINT", "packetsSelected", ""],
    [0, IPFIXFieldType.FIXEDERROR, 8, "IPFIX_CODING_FLOAT", "fixedError", ""],
    [0, IPFIXFieldType.RELATIVEERROR, 8, "IPFIX_CODING_FLOAT", "relativeError", ""],
    [0, IPFIXFieldType.OBSERVATIONTIMESECONDS, 4, "IPFIX_CODING_UINT", "observationTimeSeconds", ""],
    [0, IPFIXFieldType.OBSERVATIONTIMEMILLISECONDS, 8, "IPFIX_CODING_UINT", "observationTimeMilliseconds", ""],
    [0, IPFIXFieldType.OBSERVATIONTIMEMICROSECONDS, 8, "IPFIX_CODING_NTP", "observationTimeMicroseconds", ""],
    [0, IPFIXFieldType.OBSERVATIONTIMENANOSECONDS, 8, "IPFIX_CODING_NTP", "observationTimeNanoseconds", ""],
    [0, IPFIXFieldType.DIGESTHASHVALUE, 8, "IPFIX_CODING_UINT", "digestHashValue", ""],
    [0, IPFIXFieldType.HASHIPPAYLOADOFFSET, 8, "IPFIX_CODING_UINT", "hashIPPayloadOffset", ""],
    [0, IPFIXFieldType.HASHIPPAYLOADSIZE, 8, "IPFIX_CODING_UINT", "hashIPPayloadSize", ""],
    [0, IPFIXFieldType.HASHOUTPUTRANGEMIN, 8, "IPFIX_CODING_UINT", "hashOutputRangeMin", ""],
    [0, IPFIXFieldType.HASHOUTPUTRANGEMAX, 8, "IPFIX_CODING_UINT", "hashOutputRangeMax", ""],
    [0, IPFIXFieldType.HASHSELECTEDRANGEMIN, 8, "IPFIX_CODING_UINT", "hashSelectedRangeMin", ""],
    [0, IPFIXFieldType.HASHSELECTEDRANGEMAX, 8, "IPFIX_CODING_UINT", "hashSelectedRangeMax", ""],
    [0, IPFIXFieldType.HASHDIGESTOUTPUT, 1, "IPFIX_CODING_BYTES", "hashDigestOutput", ""],
    [0, IPFIXFieldType.HASHINITIALISERVALUE, 8, "IPFIX_CODING_UINT", "hashInitialiserValue", ""],
]

# Determine the highest ftype
max_ftype = 335

# Initialize the full array with empty slots
full_array: List[Dict] = [{"eno": 0, "ftype": i, "length": 0, "coding": 0, "name": None, "documentation": None} for i in
                          range(max_ftype + 1)]

# Fill in the known entries at their ftype index
for entry in original_entries:
    full_array[entry[1]] = {"eno": entry[0], "ftype": entry[1], "length": entry[2], "coding": entry[3],
                            "name": entry[4], "documentation": entry[5]}
    # Generate C-style formatted lines


def format_entry(entry):
    test_ipfix = False
    try:
        IPFIXFieldType(entry["ftype"])
        test_ipfix = True
    except Exception as e:
        test_ipfix = False
    if test_ipfix is False:
        ret = f"    {{0, {entry['ftype']}, 0, NULL, NULL, NULL}},"
    else:
        ret = f"    {{{entry['eno']}, IPFIX_FT_{IPFIXFieldType(entry['ftype']).name}, {entry['length']},{entry['coding']},\"{entry['name']}\", \"{entry['documentation']}\"}},"

    return ret


formatted_lines = [format_entry(entry)
                   for entry in full_array]

# Add terminating entry
formatted_lines.append("    {0, 0, -1, 0, NULL, NULL}")

for ftype in IPFIXFieldType:
    print(f"#define IPFIX_FT_{ftype.name} {ftype.value}")

# Wrap with array definition
formatted_array = "ipfix_field_type_t ipfix_field_types[] = {\n" + "\n".join(formatted_lines) + "\n};"
print(formatted_array)
