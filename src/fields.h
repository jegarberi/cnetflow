//
// Created by jon on 6/13/25.
//

#ifndef FIELDS_H
#define FIELDS_H

#define IPFIX_CODING_INT    1
#define IPFIX_CODING_UINT   2
#define IPFIX_CODING_BYTES  3
#define IPFIX_CODING_STRING 4
#define IPFIX_CODING_FLOAT  5
#define IPFIX_CODING_NTP    6
#define IPFIX_CODING_IPADDR 7

#define REV_PEN 29305 /* reverse elements private enterprise number, see RFC5103 */

typedef struct
{
  int         eno;                /* enterprise number or 0 */
  int         ftype;              /* field type */
  ssize_t     length;             /* field length */
  int         coding;
  char        *name;
  char        *documentation;

} ipfix_field_type_t;

#define IPFIX_FT_OCTETDELTACOUNT              1
#define IPFIX_FT_PACKETDELTACOUNT             2
#define IPFIX_FT_FLOWS                        3
#define IPFIX_FT_PROTOCOLIDENTIFIER           4
#define IPFIX_FT_IPCLASSOFSERVICE             5
#define IPFIX_FT_TCPCONTROLBITS               6
#define IPFIX_FT_SOURCETRANSPORTPORT          7
#define IPFIX_FT_SOURCEIPV4ADDRESS            8
#define IPFIX_FT_SOURCEIPV4PREFIXLENGTH       9
#define IPFIX_FT_INGRESSINTERFACE             10
#define IPFIX_FT_DESTINATIONTRANSPORTPORT     11
#define IPFIX_FT_DESTINATIONIPV4ADDRESS       12
#define IPFIX_FT_DESTINATIONIPV4PREFIXLENGTH  13
#define IPFIX_FT_EGRESSINTERFACE              14
#define IPFIX_FT_IPNEXTHOPIPV4ADDRESS         15
#define IPFIX_FT_BGPSOURCEASNUMBER            16
#define IPFIX_FT_BGPDESTINATIONASNUMBER       17
#define IPFIX_FT_BGPNEXTHOPIPV4ADDRESS        18
#define IPFIX_FT_POSTMCASTPACKETDELTACOUNT    19
#define IPFIX_FT_POSTMCASTOCTETDELTACOUNT     20
#define IPFIX_FT_FLOWENDSYSUPTIME             21
#define IPFIX_FT_FLOWSTARTSYSUPTIME           22
#define IPFIX_FT_POSTOCTETDELTACOUNT          23
#define IPFIX_FT_POSTPACKETDELTACOUNT         24
#define IPFIX_FT_MINIMUMIPTOTALLENGTH         25
#define IPFIX_FT_MAXIMUMIPTOTALLENGTH         26
#define IPFIX_FT_SOURCEIPV6ADDRESS            27
#define IPFIX_FT_DESTINATIONIPV6ADDRESS       28
#define IPFIX_FT_SOURCEIPV6PREFIXLENGTH       29
#define IPFIX_FT_DESTINATIONIPV6PREFIXLENGTH  30
#define IPFIX_FT_FLOWLABELIPV6                31
#define IPFIX_FT_ICMPTYPECODEIPV4             32
#define IPFIX_FT_IGMPTYPE                     33
#define IPFIX_FT_SAMPLING_INTERVAL            34
#define IPFIX_FT_SAMPLING_ALGORITHM           35
#define IPFIX_FT_FLOWACTIVETIMEOUT            36
#define IPFIX_FT_FLOWIDLETIMEOUT              37
#define IPFIX_FT_ENGINE_TYPE                  38
#define IPFIX_FT_ENGINE_ID                    39
#define IPFIX_FT_EXPORTEDOCTETTOTALCOUNT      40
#define IPFIX_FT_EXPORTEDMESSAGETOTALCOUNT    41
#define IPFIX_FT_EXPORTEDFLOWRECORDTOTALCOUNT 42
#define IPFIX_FT_SOURCEIPV4PREFIX             44
#define IPFIX_FT_DESTINATIONIPV4PREFIX        45
#define IPFIX_FT_MPLSTOPLABELTYPE             46
#define IPFIX_FT_MPLSTOPLABELIPV4ADDRESS      47
#define IPFIX_FT_FLOW_SAMPLER_ID              48
#define IPFIX_FT_FLOW_SAMPLER_MODE            49
#define IPFIX_FT_FLOW_SAMPLER_RANDOM_INTERVAL 50
#define IPFIX_FT_MINIMUMTTL                   52
#define IPFIX_FT_MAXIMUMTTL                   53
#define IPFIX_FT_FRAGMENTIDENTIFICATION       54
#define IPFIX_FT_POSTIPCLASSOFSERVICE         55
#define IPFIX_FT_SOURCEMACADDRESS             56
#define IPFIX_FT_POSTDESTINATIONMACADDRESS    57
#define IPFIX_FT_VLANID                       58
#define IPFIX_FT_POSTVLANID                   59
#define IPFIX_FT_IPVERSION                    60
#define IPFIX_FT_FLOWDIRECTION                61
#define IPFIX_FT_IPNEXTHOPIPV6ADDRESS         62
#define IPFIX_FT_BGPNEXTHOPIPV6ADDRESS        63
#define IPFIX_FT_IPV6EXTENSIONHEADERS         64
#define IPFIX_FT_MPLSTOPLABELSTACKSECTION     70
#define IPFIX_FT_MPLSLABELSTACKSECTION2       71
#define IPFIX_FT_MPLSLABELSTACKSECTION3       72
#define IPFIX_FT_MPLSLABELSTACKSECTION4       73
#define IPFIX_FT_MPLSLABELSTACKSECTION5       74
#define IPFIX_FT_MPLSLABELSTACKSECTION6       75
#define IPFIX_FT_MPLSLABELSTACKSECTION7       76
#define IPFIX_FT_MPLSLABELSTACKSECTION8       77
#define IPFIX_FT_MPLSLABELSTACKSECTION9       78
#define IPFIX_FT_MPLSLABELSTACKSECTION10      79
#define IPFIX_FT_DESTINATIONMACADDRESS        80
#define IPFIX_FT_POSTSOURCEMACADDRESS         81
#define IPFIX_FT_OCTETTOTALCOUNT              85
#define IPFIX_FT_PACKETTOTALCOUNT             86
#define IPFIX_FT_FRAGMENTOFFSET               88
#define IPFIX_FT_MPLSVPNROUTEDISTINGUISHER    90
#define IPFIX_FT_BGPNEXTADJACENTASNUMBER      128
#define IPFIX_FT_BGPPREVADJACENTASNUMBER      129
#define IPFIX_FT_EXPORTERIPV4ADDRESS          130
#define IPFIX_FT_EXPORTERIPV6ADDRESS          131
#define IPFIX_FT_DROPPEDOCTETDELTACOUNT       132
#define IPFIX_FT_DROPPEDPACKETDELTACOUNT      133
#define IPFIX_FT_DROPPEDOCTETTOTALCOUNT       134
#define IPFIX_FT_DROPPEDPACKETTOTALCOUNT      135
#define IPFIX_FT_FLOWENDREASON                136
#define IPFIX_FT_COMMONPROPERTIESID           137
#define IPFIX_FT_OBSERVATIONPOINTID           138
#define IPFIX_FT_ICMPTYPECODEIPV6             139
#define IPFIX_FT_MPLSTOPLABELIPV6ADDRESS      140
#define IPFIX_FT_LINECARDID                   141
#define IPFIX_FT_PORTID                       142
#define IPFIX_FT_METERINGPROCESSID            143
#define IPFIX_FT_EXPORTINGPROCESSID           144
#define IPFIX_FT_TEMPLATEID                   145
#define IPFIX_FT_WLANCHANNELID                146
#define IPFIX_FT_WLANSSID                     147
#define IPFIX_FT_FLOWID                       148
#define IPFIX_FT_OBSERVATIONDOMAINID          149
#define IPFIX_FT_FLOWSTARTSECONDS             150
#define IPFIX_FT_FLOWENDSECONDS               151
#define IPFIX_FT_FLOWSTARTMILLISECONDS        152
#define IPFIX_FT_FLOWENDMILLISECONDS          153
#define IPFIX_FT_FLOWSTARTMICROSECONDS        154
#define IPFIX_FT_FLOWENDMICROSECONDS          155
#define IPFIX_FT_FLOWSTARTNANOSECONDS         156
#define IPFIX_FT_FLOWENDNANOSECONDS           157
#define IPFIX_FT_FLOWSTARTDELTAMICROSECONDS   158
#define IPFIX_FT_FLOWENDDELTAMICROSECONDS     159
#define IPFIX_FT_SYSTEMINITTIMEMILLISECONDS   160
#define IPFIX_FT_FLOWDURATIONMILLISECONDS     161
#define IPFIX_FT_FLOWDURATIONMICROSECONDS     162
#define IPFIX_FT_OBSERVEDFLOWTOTALCOUNT       163
#define IPFIX_FT_IGNOREDPACKETTOTALCOUNT      164
#define IPFIX_FT_IGNOREDOCTETTOTALCOUNT       165
#define IPFIX_FT_NOTSENTFLOWTOTALCOUNT        166
#define IPFIX_FT_NOTSENTPACKETTOTALCOUNT      167
#define IPFIX_FT_NOTSENTOCTETTOTALCOUNT       168
#define IPFIX_FT_DESTINATIONIPV6PREFIX        169
#define IPFIX_FT_SOURCEIPV6PREFIX             170
#define IPFIX_FT_POSTOCTETTOTALCOUNT          171
#define IPFIX_FT_POSTPACKETTOTALCOUNT         172
#define IPFIX_FT_FLOWKEYINDICATOR             173
#define IPFIX_FT_POSTMCASTPACKETTOTALCOUNT    174
#define IPFIX_FT_POSTMCASTOCTETTOTALCOUNT     175
#define IPFIX_FT_ICMPTYPEIPV4                 176
#define IPFIX_FT_ICMPCODEIPV4                 177
#define IPFIX_FT_ICMPTYPEIPV6                 178
#define IPFIX_FT_ICMPCODEIPV6                 179
#define IPFIX_FT_UDPSOURCEPORT                180
#define IPFIX_FT_UDPDESTINATIONPORT           181
#define IPFIX_FT_TCPSOURCEPORT                182
#define IPFIX_FT_TCPDESTINATIONPORT           183
#define IPFIX_FT_TCPSEQUENCENUMBER            184
#define IPFIX_FT_TCPACKNOWLEDGEMENTNUMBER     185
#define IPFIX_FT_TCPWINDOWSIZE                186
#define IPFIX_FT_TCPURGENTPOINTER             187
#define IPFIX_FT_TCPHEADERLENGTH              188
#define IPFIX_FT_IPHEADERLENGTH               189
#define IPFIX_FT_TOTALLENGTHIPV4              190
#define IPFIX_FT_PAYLOADLENGTHIPV6            191
#define IPFIX_FT_IPTTL                        192
#define IPFIX_FT_NEXTHEADERIPV6               193
#define IPFIX_FT_MPLSPAYLOADLENGTH            194
#define IPFIX_FT_IPDIFFSERVCODEPOINT          195
#define IPFIX_FT_IPPRECEDENCE                 196
#define IPFIX_FT_FRAGMENTFLAGS                197
#define IPFIX_FT_OCTETDELTASUMOFSQUARES       198
#define IPFIX_FT_OCTETTOTALSUMOFSQUARES       199
#define IPFIX_FT_MPLSTOPLABELTTL              200
#define IPFIX_FT_MPLSLABELSTACKLENGTH         201
#define IPFIX_FT_MPLSLABELSTACKDEPTH          202
#define IPFIX_FT_MPLSTOPLABELEXP              203
#define IPFIX_FT_IPPAYLOADLENGTH              204
#define IPFIX_FT_UDPMESSAGELENGTH             205
#define IPFIX_FT_ISMULTICAST                  206
#define IPFIX_FT_IPV4IHL                      207
#define IPFIX_FT_IPV4OPTIONS                  208
#define IPFIX_FT_TCPOPTIONS                   209
#define IPFIX_FT_PADDINGOCTETS                210
#define IPFIX_FT_COLLECTORIPV4ADDRESS         211
#define IPFIX_FT_COLLECTORIPV6ADDRESS         212
#define IPFIX_FT_COLLECTORINTERFACE           213
#define IPFIX_FT_COLLECTORPROTOCOLVERSION     214
#define IPFIX_FT_COLLECTORTRANSPORTPROTOCOL   215
#define IPFIX_FT_COLLECTORTRANSPORTPORT       216
#define IPFIX_FT_EXPORTERTRANSPORTPORT        217
#define IPFIX_FT_TCPSYNTOTALCOUNT             218
#define IPFIX_FT_TCPFINTOTALCOUNT             219
#define IPFIX_FT_TCPRSTTOTALCOUNT             220
#define IPFIX_FT_TCPPSHTOTALCOUNT             221
#define IPFIX_FT_TCPACKTOTALCOUNT             222
#define IPFIX_FT_TCPURGTOTALCOUNT             223
#define IPFIX_FT_IPTOTALLENGTH                224
#define postNATSourceIPv4Address              225
#define postNATDestinationIPv4Address         226
#define postNAPTSourceTransportPort           227
#define postNAPTDestinationTransportPort      228
#define NATEventType                          230
#define biflowDirection                       239
#define IPFIX_FT_POSTMPLSTOPLABELEXP          237
#define IPFIX_FT_TCPWINDOWSCALE               238
#define IPFIX_FT_OBSERVATIONPOINTID_PSAMP     300
#define IPFIX_FT_SELECTIONSEQUENCEID          301
#define IPFIX_FT_SELECTORID                   302
#define IPFIX_FT_INFORMATIONELEMENTID         303
#define IPFIX_FT_SELECTORALGORITHM            304
#define IPFIX_FT_SAMPLINGPACKETINTERVAL       305
#define IPFIX_FT_SAMPLINGPACKETSPACE          306
#define IPFIX_FT_SAMPLINGTIMEINTERVAL         307
#define IPFIX_FT_SAMPLINGTIMESPACE            308
#define IPFIX_FT_SAMPLINGSIZE                 309
#define IPFIX_FT_SAMPLINGPOPULATION           310
#define IPFIX_FT_SAMPLINGPROBABILITY          311
#define IPFIX_FT_DATALINKFRAMESIZE            312
#define IPFIX_FT_IPHEADERPACKETSECTION        313
#define IPFIX_FT_IPPAYLOADPACKETSECTION       314
#define IPFIX_FT_DATALINKFRAMESECTION         315
#define IPFIX_FT_MPLSLABELSTACKSECTION        316
#define IPFIX_FT_MPLSPAYLOADPACKETSECTION     317
#define IPFIX_FT_PACKETSOBSERVED              318
#define IPFIX_FT_PACKETSSELECTED              319
#define IPFIX_FT_FIXEDERROR                   320
#define IPFIX_FT_RELATIVEERROR                321
#define IPFIX_FT_OBSERVATIONTIMESECONDS       322
#define IPFIX_FT_OBSERVATIONTIMEMILLISECONDS  323
#define IPFIX_FT_OBSERVATIONTIMEMICROSECONDS  324
#define IPFIX_FT_OBSERVATIONTIMENANOSECONDS   325
#define IPFIX_FT_DIGESTHASHVALUE              326
#define IPFIX_FT_HASHIPPAYLOADOFFSET          327
#define IPFIX_FT_HASHIPPAYLOADSIZE            328
#define IPFIX_FT_HASHOUTPUTRANGEMIN           329
#define IPFIX_FT_HASHOUTPUTRANGEMAX           330
#define IPFIX_FT_HASHSELECTEDRANGEMIN         331
#define IPFIX_FT_HASHSELECTEDRANGEMAX         332
#define IPFIX_FT_HASHDIGESTOUTPUT             333
#define IPFIX_FT_HASHINITIALISERVALUE         334

/* column name definitions
 */
#define IPFIX_CN_OCTETDELTACOUNT              "ie0_1"
#define IPFIX_CN_PACKETDELTACOUNT             "ie0_2"
#define IPFIX_CN_FLOWS                        "ie0_3"
#define IPFIX_CN_PROTOCOLIDENTIFIER           "ie0_4"
#define IPFIX_CN_IPCLASSOFSERVICE             "ie0_5"
#define IPFIX_CN_TCPCONTROLBITS               "ie0_6"
#define IPFIX_CN_SOURCETRANSPORTPORT          "ie0_7"
#define IPFIX_CN_SOURCEIPV4ADDRESS            "ie0_8"
#define IPFIX_CN_SOURCEIPV4PREFIXLENGTH       "ie0_9"
#define IPFIX_CN_INGRESSINTERFACE             "ie0_a"
#define IPFIX_CN_DESTINATIONTRANSPORTPORT     "ie0_b"
#define IPFIX_CN_DESTINATIONIPV4ADDRESS       "ie0_c"
#define IPFIX_CN_DESTINATIONIPV4PREFIXLENGTH  "ie0_d"
#define IPFIX_CN_EGRESSINTERFACE              "ie0_e"
#define IPFIX_CN_IPNEXTHOPIPV4ADDRESS         "ie0_f"
#define IPFIX_CN_BGPSOURCEASNUMBER            "ie0_10"
#define IPFIX_CN_BGPDESTINATIONASNUMBER       "ie0_11"
#define IPFIX_CN_BGPNEXTHOPIPV4ADDRESS        "ie0_12"
#define IPFIX_CN_POSTMCASTPACKETDELTACOUNT    "ie0_13"
#define IPFIX_CN_POSTMCASTOCTETDELTACOUNT     "ie0_14"
#define IPFIX_CN_FLOWENDSYSUPTIME             "ie0_15"
#define IPFIX_CN_FLOWSTARTSYSUPTIME           "ie0_16"
#define IPFIX_CN_POSTOCTETDELTACOUNT          "ie0_17"
#define IPFIX_CN_POSTPACKETDELTACOUNT         "ie0_18"
#define IPFIX_CN_MINIMUMIPTOTALLENGTH         "ie0_19"
#define IPFIX_CN_MAXIMUMIPTOTALLENGTH         "ie0_1a"
#define IPFIX_CN_SOURCEIPV6ADDRESS            "ie0_1b"
#define IPFIX_CN_DESTINATIONIPV6ADDRESS       "ie0_1c"
#define IPFIX_CN_SOURCEIPV6PREFIXLENGTH       "ie0_1d"
#define IPFIX_CN_DESTINATIONIPV6PREFIXLENGTH  "ie0_1e"
#define IPFIX_CN_FLOWLABELIPV6                "ie0_1f"
#define IPFIX_CN_ICMPTYPECODEIPV4             "ie0_20"
#define IPFIX_CN_IGMPTYPE                     "ie0_21"
#define IPFIX_CN_SAMPLING_INTERVAL            "ie0_22"
#define IPFIX_CN_SAMPLING_ALGORITHM           "ie0_23"
#define IPFIX_CN_FLOWACTIVETIMEOUT            "ie0_24"
#define IPFIX_CN_FLOWIDLETIMEOUT              "ie0_25"
#define IPFIX_CN_ENGINE_TYPE                  "ie0_26"
#define IPFIX_CN_ENGINE_ID                    "ie0_27"
#define IPFIX_CN_EXPORTEDOCTETTOTALCOUNT      "ie0_28"
#define IPFIX_CN_EXPORTEDMESSAGETOTALCOUNT    "ie0_29"
#define IPFIX_CN_EXPORTEDFLOWRECORDTOTALCOUNT "ie0_2a"
#define IPFIX_CN_SOURCEIPV4PREFIX             "ie0_2c"
#define IPFIX_CN_DESTINATIONIPV4PREFIX        "ie0_2d"
#define IPFIX_CN_MPLSTOPLABELTYPE             "ie0_2e"
#define IPFIX_CN_MPLSTOPLABELIPV4ADDRESS      "ie0_2f"
#define IPFIX_CN_FLOW_SAMPLER_ID              "ie0_30"
#define IPFIX_CN_FLOW_SAMPLER_MODE            "ie0_31"
#define IPFIX_CN_FLOW_SAMPLER_RANDOM_INTERVAL "ie0_32"
#define IPFIX_CN_MINIMUMTTL                   "ie0_34"
#define IPFIX_CN_MAXIMUMTTL                   "ie0_35"
#define IPFIX_CN_FRAGMENTIDENTIFICATION       "ie0_36"
#define IPFIX_CN_POSTIPCLASSOFSERVICE         "ie0_37"
#define IPFIX_CN_SOURCEMACADDRESS             "ie0_38"
#define IPFIX_CN_POSTDESTINATIONMACADDRESS    "ie0_39"
#define IPFIX_CN_VLANID                       "ie0_3a"
#define IPFIX_CN_POSTVLANID                   "ie0_3b"
#define IPFIX_CN_IPVERSION                    "ie0_3c"
#define IPFIX_CN_FLOWDIRECTION                "ie0_3d"
#define IPFIX_CN_IPNEXTHOPIPV6ADDRESS         "ie0_3e"
#define IPFIX_CN_BGPNEXTHOPIPV6ADDRESS        "ie0_3f"
#define IPFIX_CN_IPV6EXTENSIONHEADERS         "ie0_40"
#define IPFIX_CN_MPLSTOPLABELSTACKSECTION     "ie0_46"
#define IPFIX_CN_MPLSLABELSTACKSECTION2       "ie0_47"
#define IPFIX_CN_MPLSLABELSTACKSECTION3       "ie0_48"
#define IPFIX_CN_MPLSLABELSTACKSECTION4       "ie0_49"
#define IPFIX_CN_MPLSLABELSTACKSECTION5       "ie0_4a"
#define IPFIX_CN_MPLSLABELSTACKSECTION6       "ie0_4b"
#define IPFIX_CN_MPLSLABELSTACKSECTION7       "ie0_4c"
#define IPFIX_CN_MPLSLABELSTACKSECTION8       "ie0_4d"
#define IPFIX_CN_MPLSLABELSTACKSECTION9       "ie0_4e"
#define IPFIX_CN_MPLSLABELSTACKSECTION10      "ie0_4f"
#define IPFIX_CN_DESTINATIONMACADDRESS        "ie0_50"
#define IPFIX_CN_POSTSOURCEMACADDRESS         "ie0_51"
#define IPFIX_CN_OCTETTOTALCOUNT              "ie0_55"
#define IPFIX_CN_PACKETTOTALCOUNT             "ie0_56"
#define IPFIX_CN_FRAGMENTOFFSET               "ie0_58"
#define IPFIX_CN_MPLSVPNROUTEDISTINGUISHER    "ie0_5a"
#define IPFIX_CN_BGPNEXTADJACENTASNUMBER      "ie0_80"
#define IPFIX_CN_BGPPREVADJACENTASNUMBER      "ie0_81"
#define IPFIX_CN_EXPORTERIPV4ADDRESS          "ie0_82"
#define IPFIX_CN_EXPORTERIPV6ADDRESS          "ie0_83"
#define IPFIX_CN_DROPPEDOCTETDELTACOUNT       "ie0_84"
#define IPFIX_CN_DROPPEDPACKETDELTACOUNT      "ie0_85"
#define IPFIX_CN_DROPPEDOCTETTOTALCOUNT       "ie0_86"
#define IPFIX_CN_DROPPEDPACKETTOTALCOUNT      "ie0_87"
#define IPFIX_CN_FLOWENDREASON                "ie0_88"
#define IPFIX_CN_COMMONPROPERTIESID           "ie0_89"
#define IPFIX_CN_OBSERVATIONPOINTID           "ie0_8a"
#define IPFIX_CN_ICMPTYPECODEIPV6             "ie0_8b"
#define IPFIX_CN_MPLSTOPLABELIPV6ADDRESS      "ie0_8c"
#define IPFIX_CN_LINECARDID                   "ie0_8d"
#define IPFIX_CN_PORTID                       "ie0_8e"
#define IPFIX_CN_METERINGPROCESSID            "ie0_8f"
#define IPFIX_CN_EXPORTINGPROCESSID           "ie0_90"
#define IPFIX_CN_TEMPLATEID                   "ie0_91"
#define IPFIX_CN_WLANCHANNELID                "ie0_92"
#define IPFIX_CN_WLANSSID                     "ie0_93"
#define IPFIX_CN_FLOWID                       "ie0_94"
#define IPFIX_CN_OBSERVATIONDOMAINID          "ie0_95"
#define IPFIX_CN_FLOWSTARTSECONDS             "ie0_96"
#define IPFIX_CN_FLOWENDSECONDS               "ie0_97"
#define IPFIX_CN_FLOWSTARTMILLISECONDS        "ie0_98"
#define IPFIX_CN_FLOWENDMILLISECONDS          "ie0_99"
#define IPFIX_CN_FLOWSTARTMICROSECONDS        "ie0_9a"
#define IPFIX_CN_FLOWENDMICROSECONDS          "ie0_9b"
#define IPFIX_CN_FLOWSTARTNANOSECONDS         "ie0_9c"
#define IPFIX_CN_FLOWENDNANOSECONDS           "ie0_9d"
#define IPFIX_CN_FLOWSTARTDELTAMICROSECONDS   "ie0_9e"
#define IPFIX_CN_FLOWENDDELTAMICROSECONDS     "ie0_9f"
#define IPFIX_CN_SYSTEMINITTIMEMILLISECONDS   "ie0_a0"
#define IPFIX_CN_FLOWDURATIONMILLISECONDS     "ie0_a1"
#define IPFIX_CN_FLOWDURATIONMICROSECONDS     "ie0_a2"
#define IPFIX_CN_OBSERVEDFLOWTOTALCOUNT       "ie0_a3"
#define IPFIX_CN_IGNOREDPACKETTOTALCOUNT      "ie0_a4"
#define IPFIX_CN_IGNOREDOCTETTOTALCOUNT       "ie0_a5"
#define IPFIX_CN_NOTSENTFLOWTOTALCOUNT        "ie0_a6"
#define IPFIX_CN_NOTSENTPACKETTOTALCOUNT      "ie0_a7"
#define IPFIX_CN_NOTSENTOCTETTOTALCOUNT       "ie0_a8"
#define IPFIX_CN_DESTINATIONIPV6PREFIX        "ie0_a9"
#define IPFIX_CN_SOURCEIPV6PREFIX             "ie0_aa"
#define IPFIX_CN_POSTOCTETTOTALCOUNT          "ie0_ab"
#define IPFIX_CN_POSTPACKETTOTALCOUNT         "ie0_ac"
#define IPFIX_CN_FLOWKEYINDICATOR             "ie0_ad"
#define IPFIX_CN_POSTMCASTPACKETTOTALCOUNT    "ie0_ae"
#define IPFIX_CN_POSTMCASTOCTETTOTALCOUNT     "ie0_af"
#define IPFIX_CN_ICMPTYPEIPV4                 "ie0_b0"
#define IPFIX_CN_ICMPCODEIPV4                 "ie0_b1"
#define IPFIX_CN_ICMPTYPEIPV6                 "ie0_b2"
#define IPFIX_CN_ICMPCODEIPV6                 "ie0_b3"
#define IPFIX_CN_UDPSOURCEPORT                "ie0_b4"
#define IPFIX_CN_UDPDESTINATIONPORT           "ie0_b5"
#define IPFIX_CN_TCPSOURCEPORT                "ie0_b6"
#define IPFIX_CN_TCPDESTINATIONPORT           "ie0_b7"
#define IPFIX_CN_TCPSEQUENCENUMBER            "ie0_b8"
#define IPFIX_CN_TCPACKNOWLEDGEMENTNUMBER     "ie0_b9"
#define IPFIX_CN_TCPWINDOWSIZE                "ie0_ba"
#define IPFIX_CN_TCPURGENTPOINTER             "ie0_bb"
#define IPFIX_CN_TCPHEADERLENGTH              "ie0_bc"
#define IPFIX_CN_IPHEADERLENGTH               "ie0_bd"
#define IPFIX_CN_TOTALLENGTHIPV4              "ie0_be"
#define IPFIX_CN_PAYLOADLENGTHIPV6            "ie0_bf"
#define IPFIX_CN_IPTTL                        "ie0_c0"
#define IPFIX_CN_NEXTHEADERIPV6               "ie0_c1"
#define IPFIX_CN_MPLSPAYLOADLENGTH            "ie0_c2"
#define IPFIX_CN_IPDIFFSERVCODEPOINT          "ie0_c3"
#define IPFIX_CN_IPPRECEDENCE                 "ie0_c4"
#define IPFIX_CN_FRAGMENTFLAGS                "ie0_c5"
#define IPFIX_CN_OCTETDELTASUMOFSQUARES       "ie0_c6"
#define IPFIX_CN_OCTETTOTALSUMOFSQUARES       "ie0_c7"
#define IPFIX_CN_MPLSTOPLABELTTL              "ie0_c8"
#define IPFIX_CN_MPLSLABELSTACKLENGTH         "ie0_c9"
#define IPFIX_CN_MPLSLABELSTACKDEPTH          "ie0_ca"
#define IPFIX_CN_MPLSTOPLABELEXP              "ie0_cb"
#define IPFIX_CN_IPPAYLOADLENGTH              "ie0_cc"
#define IPFIX_CN_UDPMESSAGELENGTH             "ie0_cd"
#define IPFIX_CN_ISMULTICAST                  "ie0_ce"
#define IPFIX_CN_IPV4IHL                      "ie0_cf"
#define IPFIX_CN_IPV4OPTIONS                  "ie0_d0"
#define IPFIX_CN_TCPOPTIONS                   "ie0_d1"
#define IPFIX_CN_PADDINGOCTETS                "ie0_d2"
#define IPFIX_CN_COLLECTORIPV4ADDRESS         "ie0_d3"
#define IPFIX_CN_COLLECTORIPV6ADDRESS         "ie0_d4"
#define IPFIX_CN_COLLECTORINTERFACE           "ie0_d5"
#define IPFIX_CN_COLLECTORPROTOCOLVERSION     "ie0_d6"
#define IPFIX_CN_COLLECTORTRANSPORTPROTOCOL   "ie0_d7"
#define IPFIX_CN_COLLECTORTRANSPORTPORT       "ie0_d8"
#define IPFIX_CN_EXPORTERTRANSPORTPORT        "ie0_d9"
#define IPFIX_CN_TCPSYNTOTALCOUNT             "ie0_da"
#define IPFIX_CN_TCPFINTOTALCOUNT             "ie0_db"
#define IPFIX_CN_TCPRSTTOTALCOUNT             "ie0_dc"
#define IPFIX_CN_TCPPSHTOTALCOUNT             "ie0_dd"
#define IPFIX_CN_TCPACKTOTALCOUNT             "ie0_de"
#define IPFIX_CN_TCPURGTOTALCOUNT             "ie0_df"
#define IPFIX_CN_IPTOTALLENGTH                "ie0_e0"
#define IPFIX_CN_POSTMPLSTOPLABELEXP          "ie0_ed"
#define IPFIX_CN_TCPWINDOWSCALE               "ie0_ee"
#define IPFIX_CN_OBSERVATIONPOINTID_PSAMP     "ie0_12c"
#define IPFIX_CN_SELECTIONSEQUENCEID          "ie0_12d"
#define IPFIX_CN_SELECTORID                   "ie0_12e"
#define IPFIX_CN_INFORMATIONELEMENTID         "ie0_12f"
#define IPFIX_CN_SELECTORALGORITHM            "ie0_130"
#define IPFIX_CN_SAMPLINGPACKETINTERVAL       "ie0_131"
#define IPFIX_CN_SAMPLINGPACKETSPACE          "ie0_132"
#define IPFIX_CN_SAMPLINGTIMEINTERVAL         "ie0_133"
#define IPFIX_CN_SAMPLINGTIMESPACE            "ie0_134"
#define IPFIX_CN_SAMPLINGSIZE                 "ie0_135"
#define IPFIX_CN_SAMPLINGPOPULATION           "ie0_136"
#define IPFIX_CN_SAMPLINGPROBABILITY          "ie0_137"
#define IPFIX_CN_DATALINKFRAMESIZE            "ie0_138"
#define IPFIX_CN_IPHEADERPACKETSECTION        "ie0_139"
#define IPFIX_CN_IPPAYLOADPACKETSECTION       "ie0_13a"
#define IPFIX_CN_DATALINKFRAMESECTION         "ie0_13b"
#define IPFIX_CN_MPLSLABELSTACKSECTION        "ie0_13c"
#define IPFIX_CN_MPLSPAYLOADPACKETSECTION     "ie0_13d"
#define IPFIX_CN_PACKETSOBSERVED              "ie0_13e"
#define IPFIX_CN_PACKETSSELECTED              "ie0_13f"
#define IPFIX_CN_FIXEDERROR                   "ie0_140"
#define IPFIX_CN_RELATIVEERROR                "ie0_141"
#define IPFIX_CN_OBSERVATIONTIMESECONDS       "ie0_142"
#define IPFIX_CN_OBSERVATIONTIMEMILLISECONDS  "ie0_143"
#define IPFIX_CN_OBSERVATIONTIMEMICROSECONDS  "ie0_144"
#define IPFIX_CN_OBSERVATIONTIMENANOSECONDS   "ie0_145"
#define IPFIX_CN_DIGESTHASHVALUE              "ie0_146"
#define IPFIX_CN_HASHIPPAYLOADOFFSET          "ie0_147"
#define IPFIX_CN_HASHIPPAYLOADSIZE            "ie0_148"
#define IPFIX_CN_HASHOUTPUTRANGEMIN           "ie0_149"
#define IPFIX_CN_HASHOUTPUTRANGEMAX           "ie0_14a"
#define IPFIX_CN_HASHSELECTEDRANGEMIN         "ie0_14b"
#define IPFIX_CN_HASHSELECTEDRANGEMAX         "ie0_14c"
#define IPFIX_CN_HASHDIGESTOUTPUT             "ie0_14d"
#define IPFIX_CN_HASHINITIALISERVALUE         "ie0_14e"








#define IPFIX_ENO_FOKUS	12325


#define  IPFIX_FT_REVOCTETDELTACOUNT 	 176
#define  IPFIX_FT_REVPACKETDELTACOUNT 	 177
#define  IPFIX_FT_RTTMEAN_USEC 	 178
#define  IPFIX_FT_RTTMIN_USEC 	 179
#define  IPFIX_FT_RTTMAX_USEC 	 180
#define  IPFIX_FT_IDENT 	 181
#define  IPFIX_FT_LOSTPACKETS 	 182
#define  IPFIX_FT_OWDVAR_USEC 	 183
#define  IPFIX_FT_OWDVARMEAN_USEC 	 184
#define  IPFIX_FT_OWDVARMIN_USEC 	 185
#define  IPFIX_FT_OWDVARMAX_USEC 	 186
#define  IPFIX_FT_OWDSD_USEC 	 187
#define  IPFIX_FT_OWD_USEC 	 188
#define  IPFIX_FT_OWDMEAN_USEC 	 189
#define  IPFIX_FT_OWDMIN_USEC 	 190
#define  IPFIX_FT_OWDMAX_USEC 	 191
#define  IPFIX_FT_TASKID 	 192
#define  IPFIX_FT_TSTAMP_SEC 	 193
#define  IPFIX_FT_TSTAMP_NSEC 	 194
#define  IPFIX_FT_PKTLENGTH 	 195
#define  IPFIX_FT_PKTID 	 196
#define  IPFIX_FT_STARTTIME 	 197
#define  IPFIX_FT_ENDTIME 	 198
#define  IPFIX_FT_RTT_USEC 	 199
#define  IPFIX_FT_FLOWCREATIONTIMEUSEC 	 300
#define  IPFIX_FT_FLOWENDTIMEUSEC 	 301
#define  IPFIX_FT_TC_PACKETS 	 303
#define  IPFIX_FT_TC_BYTES 	 304
#define  IPFIX_FT_TC_RATE_BPS 	 305
#define  IPFIX_FT_TC_RATE_PPS 	 306
#define  IPFIX_FT_TC_QLEN 	 307
#define  IPFIX_FT_TC_BACKLOG 	 308
#define  IPFIX_FT_TC_DROPS 	 309
#define  IPFIX_FT_TC_REQUEUES 	 310
#define  IPFIX_FT_TC_OVERLIMITS 	 311
#define  IPFIX_FT_OWDVARMEAN_NSEC 	 312
#define  IPFIX_FT_OWDVARMIN_NSEC 	 313
#define  IPFIX_FT_OWDVARMAX_NSEC 	 314
#define  IPFIX_FT_SOURCEIPV4FANOUT 	 315
#define  IPFIX_FT_DESTINATIONIPV4FANIN 	 316
#define  IPFIX_FT_PACKETARRIVALMEAN 	 317
#define  IPFIX_FT_PACKETARRIVALVAR 	 318
#define  IPFIX_FT_PR_SESSIONID 	 330
#define  IPFIX_FT_PR_TRANSACTIONID 	 331
#define  IPFIX_FT_PR_AES128ENCRYPTEDDATA 	 332
#define  IPFIX_FT_PR_AES256ENCRYPTEDDATA 	 337
#define  IPFIX_FT_PR_DECRYPTIONKEY 	 333
#define  IPFIX_FT_PR_AES128KEYSHARE 	 334
#define  IPFIX_FT_PR_AES256KEYSHARE 	 338
#define  IPFIX_FT_PR_KEYSHAREADP 	 335
#define  IPFIX_FT_PR_KEYSHAREINITVECTOR 	 336
#define  IPFIX_FT_PT_SYSTEM_CPU_IDLE 	 340
#define  IPFIX_FT_PT_SYSTEM_MEM_FREE 	 341
#define  IPFIX_FT_PT_PROCESS_CPU_USER 	 342
#define  IPFIX_FT_PT_PROCESS_CPU_SYS 	 343
#define  IPFIX_FT_PT_PROCESS_MEM_VZS 	 344
#define  IPFIX_FT_PT_PROCESS_MEM_RSS 	 345
#define  IPFIX_FT_PT_PCAPSTAT_RECV 	 346
#define  IPFIX_FT_PT_PCAPSTAT_DROP 	 347
#define  IPFIX_FT_PT_MESSAGE_ID 	 348
#define  IPFIX_FT_PT_MESSAGE_VALUE 	 349
#define  IPFIX_FT_PT_MESSAGE 	 350
#define  IPFIX_FT_PT_INTERFACE_NAME 	 351
#define  IPFIX_FT_PT_INTERFACE_DESCRIPTION 	 352
#define  IPFIX_FT_PT_GEO_LATITUDE 	 353
#define  IPFIX_FT_PT_GEO_LONGITUDE 	 354
#define  IPFIX_FT_PT_PROBE_NAME 	 355
#define  IPFIX_FT_PT_PROBE_LOCATION_NAME 	 356
#define  IPFIX_FT_PT_SYSTEM_MEM_TOTAL 	 357
#define  IPFIX_FT_SYNC_QUEUE_FILL_LEVEL 	 390
#define  IPFIX_FT_SYNC_BOTTLENECK 	 391
#define  IPFIX_FT_SYNC_FREQ 	 392
#define  IPFIX_FT_ORsignalBandwidth 	 402
#define  IPFIX_FT_ORsignalPower 	 403
#define  IPFIX_FT_ORsymbolRate 	 405
#define  IPFIX_FT_ORmodulationOrder 	 406
#define  IPFIX_FT_ORrolloffFactor 	 407
#define  IPFIX_FT_sensing_value 	 421
#define  IPFIX_FT_sensing_threshold 	 422
#define  IPFIX_FT_OR_terminal_id 	 423
#define  IPFIX_FT_OR_terminal_id_list 	 424
#define  IPFIX_FT_Infrastructure_network_id 	 425
#define  IPFIX_FT_Spectral_allocation_vector 	 431
#define  IPFIX_FT_Spectral_allocation_profile 	 432
#define  IPFIX_FT_Center_frequency 	 433
#define  IPFIX_FT_Bandwidth_of_CAP 	 434
#define  IPFIX_FT_ORmodulation 	 435
#define  IPFIX_FT_PT_APN 	 440
#define  IPFIX_FT_PT_RULE 	 441
#define  IPFIX_FT_PT_IMSI 	 442
#define  IPFIX_FT_PT_QCI 	 443
#define  IPFIX_FT_PT_MAX_DL 	 444
#define  IPFIX_FT_PT_MAX_UL 	 445
#define  IPFIX_FT_PT_GUARANTEED_DL 	 446
#define  IPFIX_FT_PT_GUARANTEED_UL 	 447
#define  IPFIX_FT_PT_APN_DL 	 448
#define  IPFIX_FT_PT_APN_UL 	 449
#define  IPFIX_FT_PT_RULE_FLAG 	 450
#define  IPFIX_FT_PT_RULE_ID 	 451

/*
 * column name definitions
 */
#define  IPFIX_CN_PT_RULE_ID 	  "RuleID"
#define  IPFIX_CN_PT_RULE_FLAG 	  "RuleFlag"
#define  IPFIX_CN_PT_APN_UL 	  "APNUpload"
#define  IPFIX_CN_PT_APN_DL 	  "APNDownload"
#define  IPFIX_CN_PT_GUARANTEED_UL 	  "GuaranteedUpload"
#define  IPFIX_CN_PT_GUARANTEED_DL 	  "GuaranteedDownload"
#define  IPFIX_CN_PT_MAX_UL 	  "MaxUpload"
#define  IPFIX_CN_PT_MAX_DL 	  "MaxDownload"
#define  IPFIX_CN_PT_QCI 	  "QCI"
#define  IPFIX_CN_PT_IMSI 	  "IMSI"
#define  IPFIX_CN_PT_RULE 	  "RuleName"
#define  IPFIX_CN_PT_APN 	  "APN"
#define  IPFIX_CN_ORmodulation 	  "ORmodulation"
#define  IPFIX_CN_Bandwidth_of_CAP 	  "Bandwidth_of_CAP"
#define  IPFIX_CN_Center_frequency 	  "Center_frequency"
#define  IPFIX_CN_Spectral_allocation_profile 	  "Spectral_allocation_profile"
#define  IPFIX_CN_Spectral_allocation_vector 	  "Spectral_allocation_vector"
#define  IPFIX_CN_Infrastructure_network_id 	  "Infrastructure_network_id"
#define  IPFIX_CN_OR_terminal_id_list 	  "OR_terminal_id_list"
#define  IPFIX_CN_OR_terminal_id 	  "OR_terminal_id"
#define  IPFIX_CN_sensing_threshold 	  "sensing_threshold"
#define  IPFIX_CN_sensing_value 	  "sensing_value"
#define  IPFIX_CN_ORrolloffFactor 	  "ORrolloffFactor"
#define  IPFIX_CN_ORmodulationOrder 	  "ORmodulationOrder"
#define  IPFIX_CN_ORsymbolRate 	  "ORsymbolRate"
#define  IPFIX_CN_ORsignalPower 	  "ORsignalPower"
#define  IPFIX_CN_ORsignalBandwidth 	  "ORsignalBandwidth"
#define  IPFIX_CN_SYNC_FREQ 	  "freq"
#define  IPFIX_CN_SYNC_BOTTLENECK 	  "bottleneck"
#define  IPFIX_CN_SYNC_QUEUE_FILL_LEVEL 	  "queueFillLevel"
#define  IPFIX_CN_PT_SYSTEM_MEM_TOTAL 	   "sysMemTotal"
#define  IPFIX_CN_PT_PROBE_LOCATION_NAME 	  "probeLocationName"
#define  IPFIX_CN_PT_PROBE_NAME 	  "probeName"
#define  IPFIX_CN_PT_GEO_LONGITUDE 	  "geoLongitude"
#define  IPFIX_CN_PT_GEO_LATITUDE 	  "geoLatitude"
#define  IPFIX_CN_PT_INTERFACE_DESCRIPTION 	  "interfaceDescripton"
#define  IPFIX_CN_PT_INTERFACE_NAME 	  "interfaceName"
#define  IPFIX_CN_PT_MESSAGE 	  "msg"
#define  IPFIX_CN_PT_MESSAGE_VALUE 	   "msgValue"
#define  IPFIX_CN_PT_MESSAGE_ID 	   "msgId"
#define  IPFIX_CN_PT_PCAPSTAT_DROP 	   "pcapDrop"
#define  IPFIX_CN_PT_PCAPSTAT_RECV 	   "pcapRecv"
#define  IPFIX_CN_PT_PROCESS_MEM_RSS 	   "procMemRss"
#define  IPFIX_CN_PT_PROCESS_MEM_VZS 	   "procMemVzs"
#define  IPFIX_CN_PT_PROCESS_CPU_SYS 	  "procCpuSys"
#define  IPFIX_CN_PT_PROCESS_CPU_USER 	  "procCpuUser"
#define  IPFIX_CN_PT_SYSTEM_MEM_FREE 	   "sysMemFree"
#define  IPFIX_CN_PT_SYSTEM_CPU_IDLE 	  "sysCpuIdle"
#define  IPFIX_CN_PR_KEYSHAREINITVECTOR 	  "cryptoInitVector"
#define  IPFIX_CN_PR_KEYSHAREADP 	  "keyShareAdp"
#define  IPFIX_CN_PR_AES256KEYSHARE 	  "keyShare256"
#define  IPFIX_CN_PR_AES128KEYSHARE 	  "keyShare128"
#define  IPFIX_CN_PR_DECRYPTIONKEY 	  "decryptionKey"
#define  IPFIX_CN_PR_AES256ENCRYPTEDDATA 	  "encryptedData128"
#define  IPFIX_CN_PR_AES128ENCRYPTEDDATA 	  "encryptedData128"
#define  IPFIX_CN_PR_TRANSACTIONID 	  "transactionId"
#define  IPFIX_CN_PR_SESSIONID 	  "sessionId"
#define  IPFIX_CN_PACKETARRIVALVAR 	 "packetArrivalVar"
#define  IPFIX_CN_PACKETARRIVALMEAN 	 "packetArrivalMean"
#define  IPFIX_CN_DESTINATIONIPV4FANIN 	 "destinationIPv4FanIn"
#define  IPFIX_CN_SOURCEIPV4FANOUT 	 "sourceIPv4FanOut"
#define  IPFIX_CN_OWDVARMAX_NSEC 	  "owdvarmax_nsec"
#define  IPFIX_CN_OWDVARMIN_NSEC 	  "owdvarmin_nsec"
#define  IPFIX_CN_OWDVARMEAN_NSEC 	  "owdvarmean_nsec"
#define  IPFIX_CN_TC_OVERLIMITS 	  "tcOverlimits"
#define  IPFIX_CN_TC_REQUEUES 	  "tcRequeues"
#define  IPFIX_CN_TC_DROPS 	  "tcDrops"
#define  IPFIX_CN_TC_BACKLOG 	  "tcbacklog"
#define  IPFIX_CN_TC_QLEN 	  "tc_qlen"
#define  IPFIX_CN_TC_RATE_PPS 	  "tcRrate_pps"
#define  IPFIX_CN_TC_RATE_BPS 	  "tcRate_bps"
#define  IPFIX_CN_TC_BYTES 	  "tcBytes"
#define  IPFIX_CN_TC_PACKETS 	  "tcPackets"
#define  IPFIX_CN_FLOWENDTIMEUSEC 	  "flowEndTimeUsec"
#define  IPFIX_CN_FLOWCREATIONTIMEUSEC 	  "flowCreationTimeUsec"
#define  IPFIX_CN_RTT_USEC 	  "rtt_usec"
#define  IPFIX_CN_ENDTIME 	  "endTime"
#define  IPFIX_CN_STARTTIME 	  "startTime"
#define  IPFIX_CN_PKTID 	  "pktId"
#define  IPFIX_CN_PKTLENGTH 	  "pktLength"
#define  IPFIX_CN_TSTAMP_NSEC 	  "tstamp_nsec"
#define  IPFIX_CN_TSTAMP_SEC 	  "tstamp_sec"
#define  IPFIX_CN_TASKID 	  "taskId"
#define  IPFIX_CN_OWDMAX_USEC 	  "owdmax_usec"
#define  IPFIX_CN_OWDMIN_USEC 	  "owdmin_usec"
#define  IPFIX_CN_OWDMEAN_USEC 	  "owdmean_usec"
#define  IPFIX_CN_OWD_USEC 	  "owd_usec"
#define  IPFIX_CN_OWDSD_USEC 	  "owdsd_usec"
#define  IPFIX_CN_OWDVARMAX_USEC 	  "owdvarmax_usec"
#define  IPFIX_CN_OWDVARMIN_USEC 	  "owdvarmin_usec"
#define  IPFIX_CN_OWDVARMEAN_USEC 	  "owdvarmean_usec"
#define  IPFIX_CN_OWDVAR_USEC 	  "owdvar_usec"
#define  IPFIX_CN_LOSTPACKETS 	  "lostPackets"
#define  IPFIX_CN_IDENT 	  "ident"
#define  IPFIX_CN_RTTMAX_USEC 	  "rttmax_usec"
#define  IPFIX_CN_RTTMIN_USEC 	  "rttmin_usec"
#define  IPFIX_CN_RTTMEAN_USEC 	  "rttmean_usec"
#define  IPFIX_CN_REVPACKETDELTACOUNT 	  "revPacketDeltaCount"



ipfix_field_type_t ipfix_field_types[] = {
  { 0, 0, 0, IPFIX_CODING_UINT,
     "none", "" },
   { 0, IPFIX_FT_OCTETDELTACOUNT, 8, IPFIX_CODING_UINT,
     "octetDeltaCount", "" },
   { 0, IPFIX_FT_PACKETDELTACOUNT, 8, IPFIX_CODING_UINT,
     "packetDeltaCount", "" },
   { 0, IPFIX_FT_FLOWS, 8, IPFIX_CODING_UINT,
     "flows", "Netflow Number of Flows that were aggregated" },
   { 0, IPFIX_FT_PROTOCOLIDENTIFIER, 1, IPFIX_CODING_UINT,
     "protocolIdentifier", "" },
   { 0, IPFIX_FT_IPCLASSOFSERVICE, 1, IPFIX_CODING_UINT,
     "ipClassOfService", "" },
   { 0, IPFIX_FT_TCPCONTROLBITS, 1, IPFIX_CODING_UINT,
     "tcpControlBits", "" },
   { 0, IPFIX_FT_SOURCETRANSPORTPORT, 2, IPFIX_CODING_UINT,
     "sourceTransportPort", "" },
   { 0, IPFIX_FT_SOURCEIPV4ADDRESS, 4, IPFIX_CODING_IPADDR,
     "sourceIPv4Address", "" },
   { 0, IPFIX_FT_SOURCEIPV4PREFIXLENGTH, 1, IPFIX_CODING_UINT,
     "sourceIPv4PrefixLength", "" },
   { 0, IPFIX_FT_INGRESSINTERFACE, 4, IPFIX_CODING_UINT,
     "ingressInterface", "" },
   { 0, IPFIX_FT_DESTINATIONTRANSPORTPORT, 2, IPFIX_CODING_UINT,
     "destinationTransportPort", "" },
   { 0, IPFIX_FT_DESTINATIONIPV4ADDRESS, 4, IPFIX_CODING_IPADDR,
     "destinationIPv4Address", "" },
   { 0, IPFIX_FT_DESTINATIONIPV4PREFIXLENGTH, 1, IPFIX_CODING_UINT,
     "destinationIPv4PrefixLength", "" },
   { 0, IPFIX_FT_EGRESSINTERFACE, 4, IPFIX_CODING_UINT,
     "egressInterface", "" },
   { 0, IPFIX_FT_IPNEXTHOPIPV4ADDRESS, 4, IPFIX_CODING_IPADDR,
     "ipNextHopIPv4Address", "" },
   { 0, IPFIX_FT_BGPSOURCEASNUMBER, 4, IPFIX_CODING_UINT,
     "bgpSourceAsNumber", "" },
   { 0, IPFIX_FT_BGPDESTINATIONASNUMBER, 4, IPFIX_CODING_UINT,
     "bgpDestinationAsNumber", "" },
   { 0, IPFIX_FT_BGPNEXTHOPIPV4ADDRESS, 4, IPFIX_CODING_IPADDR,
     "bgpNextHopIPv4Address", "" },
   { 0, IPFIX_FT_POSTMCASTPACKETDELTACOUNT, 8, IPFIX_CODING_UINT,
     "postMCastPacketDeltaCount", "" },
   { 0, IPFIX_FT_POSTMCASTOCTETDELTACOUNT, 8, IPFIX_CODING_UINT,
     "postMCastOctetDeltaCount", "" },
   { 0, IPFIX_FT_FLOWENDSYSUPTIME, 4, IPFIX_CODING_UINT,
     "flowEndSysUpTime", "" },
   { 0, IPFIX_FT_FLOWSTARTSYSUPTIME, 4, IPFIX_CODING_UINT,
     "flowStartSysUpTime", "" },
   { 0, IPFIX_FT_POSTOCTETDELTACOUNT, 8, IPFIX_CODING_UINT,
     "postOctetDeltaCount", "" },
   { 0, IPFIX_FT_POSTPACKETDELTACOUNT, 8, IPFIX_CODING_UINT,
     "postPacketDeltaCount", "" },
   { 0, IPFIX_FT_MINIMUMIPTOTALLENGTH, 8, IPFIX_CODING_UINT,
     "minimumIpTotalLength", "" },
   { 0, IPFIX_FT_MAXIMUMIPTOTALLENGTH, 8, IPFIX_CODING_UINT,
     "maximumIpTotalLength", "" },
   { 0, IPFIX_FT_SOURCEIPV6ADDRESS, 16, IPFIX_CODING_IPADDR,
     "sourceIPv6Address", "" },
   { 0, IPFIX_FT_DESTINATIONIPV6ADDRESS, 16, IPFIX_CODING_IPADDR,
     "destinationIPv6Address", "" },
   { 0, IPFIX_FT_SOURCEIPV6PREFIXLENGTH, 1, IPFIX_CODING_UINT,
     "sourceIPv6PrefixLength", "" },
   { 0, IPFIX_FT_DESTINATIONIPV6PREFIXLENGTH, 1, IPFIX_CODING_UINT,
     "destinationIPv6PrefixLength", "" },
   { 0, IPFIX_FT_FLOWLABELIPV6, 4, IPFIX_CODING_UINT,
     "flowLabelIPv6", "" },
   { 0, IPFIX_FT_ICMPTYPECODEIPV4, 2, IPFIX_CODING_UINT,
     "icmpTypeCodeIPv4", "" },
   { 0, IPFIX_FT_IGMPTYPE, 1, IPFIX_CODING_UINT,
     "igmpType", "" },
   { 0, IPFIX_FT_SAMPLING_INTERVAL, 4, IPFIX_CODING_UINT,
     "sampling_interval", "Netflow Sampling Interval" },
   { 0, IPFIX_FT_SAMPLING_ALGORITHM, 1, IPFIX_CODING_UINT,
     "sampling_algorithm", "Netflow Sampling Algorithm" },
   { 0, IPFIX_FT_FLOWACTIVETIMEOUT, 2, IPFIX_CODING_UINT,
     "flowActiveTimeout", "" },
   { 0, IPFIX_FT_FLOWIDLETIMEOUT, 2, IPFIX_CODING_UINT,
     "flowIdleTimeout", "" },
   { 0, IPFIX_FT_ENGINE_TYPE, 1, IPFIX_CODING_UINT,
     "engine_type", "Netflow Engine Type" },
   { 0, IPFIX_FT_ENGINE_ID, 1, IPFIX_CODING_UINT,
     "engine_id", "Netflow Engine ID" },
   { 0, IPFIX_FT_EXPORTEDOCTETTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "exportedOctetTotalCount", "" },
   { 0, IPFIX_FT_EXPORTEDMESSAGETOTALCOUNT, 8, IPFIX_CODING_UINT,
     "exportedMessageTotalCount", "" },
   { 0, IPFIX_FT_EXPORTEDFLOWRECORDTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "exportedFlowRecordTotalCount", "" },
   { 0, IPFIX_FT_SOURCEIPV4PREFIX, 4, IPFIX_CODING_IPADDR,
     "sourceIPv4Prefix", "" },
   { 0, IPFIX_FT_DESTINATIONIPV4PREFIX, 4, IPFIX_CODING_IPADDR,
     "destinationIPv4Prefix", "" },
   { 0, IPFIX_FT_MPLSTOPLABELTYPE, 1, IPFIX_CODING_UINT,
     "mplsTopLabelType", "" },
   { 0, IPFIX_FT_MPLSTOPLABELIPV4ADDRESS, 4, IPFIX_CODING_IPADDR,
     "mplsTopLabelIPv4Address", "" },
   { 0, IPFIX_FT_FLOW_SAMPLER_ID, 1, IPFIX_CODING_UINT,
     "flow_sampler_id", "Netflow Flow Sampler ID" },
   { 0, IPFIX_FT_FLOW_SAMPLER_MODE, 1, IPFIX_CODING_UINT,
     "flow_sampler_mode", "Netflow Flow Sampler Mode" },
   { 0, IPFIX_FT_FLOW_SAMPLER_RANDOM_INTERVAL, 4, IPFIX_CODING_UINT,
     "flow_sampler_random_interval", "Netflow Packet Sample Interval" },
   { 0, IPFIX_FT_MINIMUMTTL, 1, IPFIX_CODING_UINT,
     "minimumTTL", "" },
   { 0, IPFIX_FT_MAXIMUMTTL, 1, IPFIX_CODING_UINT,
     "maximumTTL", "" },
   { 0, IPFIX_FT_FRAGMENTIDENTIFICATION, 4, IPFIX_CODING_UINT,
     "fragmentIdentification", "" },
   { 0, IPFIX_FT_POSTIPCLASSOFSERVICE, 1, IPFIX_CODING_UINT,
     "postIpClassOfService", "" },
   { 0, IPFIX_FT_SOURCEMACADDRESS, 6, IPFIX_CODING_BYTES,
     "sourceMacAddress", "" },
   { 0, IPFIX_FT_POSTDESTINATIONMACADDRESS, 6, IPFIX_CODING_BYTES,
     "postDestinationMacAddress", "" },
   { 0, IPFIX_FT_VLANID, 2, IPFIX_CODING_UINT,
     "vlanId", "" },
   { 0, IPFIX_FT_POSTVLANID, 2, IPFIX_CODING_UINT,
     "postVlanId", "" },
   { 0, IPFIX_FT_IPVERSION, 1, IPFIX_CODING_UINT,
     "ipVersion", "" },
   { 0, IPFIX_FT_FLOWDIRECTION, 1, IPFIX_CODING_UINT,
     "flowDirection", "" },
   { 0, IPFIX_FT_IPNEXTHOPIPV6ADDRESS, 16, IPFIX_CODING_IPADDR,
     "ipNextHopIPv6Address", "" },
   { 0, IPFIX_FT_BGPNEXTHOPIPV6ADDRESS, 16, IPFIX_CODING_IPADDR,
     "bgpNextHopIPv6Address", "" },
   { 0, IPFIX_FT_IPV6EXTENSIONHEADERS, 4, IPFIX_CODING_UINT,
     "ipv6ExtensionHeaders", "" },
   { 0, IPFIX_FT_MPLSTOPLABELSTACKSECTION, 65535, IPFIX_CODING_BYTES,
     "mplsTopLabelStackSection", "" },
   { 0, IPFIX_FT_MPLSLABELSTACKSECTION2, 65535, IPFIX_CODING_BYTES,
     "mplsLabelStackSection2", "" },
   { 0, IPFIX_FT_MPLSLABELSTACKSECTION3, 65535, IPFIX_CODING_BYTES,
     "mplsLabelStackSection3", "" },
   { 0, IPFIX_FT_MPLSLABELSTACKSECTION4, 65535, IPFIX_CODING_BYTES,
     "mplsLabelStackSection4", "" },
   { 0, IPFIX_FT_MPLSLABELSTACKSECTION5, 65535, IPFIX_CODING_BYTES,
     "mplsLabelStackSection5", "" },
   { 0, IPFIX_FT_MPLSLABELSTACKSECTION6, 65535, IPFIX_CODING_BYTES,
     "mplsLabelStackSection6", "" },
   { 0, IPFIX_FT_MPLSLABELSTACKSECTION7, 65535, IPFIX_CODING_BYTES,
     "mplsLabelStackSection7", "" },
   { 0, IPFIX_FT_MPLSLABELSTACKSECTION8, 65535, IPFIX_CODING_BYTES,
     "mplsLabelStackSection8", "" },
   { 0, IPFIX_FT_MPLSLABELSTACKSECTION9, 65535, IPFIX_CODING_BYTES,
     "mplsLabelStackSection9", "" },
   { 0, IPFIX_FT_MPLSLABELSTACKSECTION10, 65535, IPFIX_CODING_BYTES,
     "mplsLabelStackSection10", "" },
   { 0, IPFIX_FT_DESTINATIONMACADDRESS, 6, IPFIX_CODING_BYTES,
     "destinationMacAddress", "" },
   { 0, IPFIX_FT_POSTSOURCEMACADDRESS, 6, IPFIX_CODING_BYTES,
     "postSourceMacAddress", "" },
   { 0, IPFIX_FT_OCTETTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "octetTotalCount", "" },
   { 0, IPFIX_FT_PACKETTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "packetTotalCount", "" },
   { 0, IPFIX_FT_FRAGMENTOFFSET, 2, IPFIX_CODING_UINT,
     "fragmentOffset", "" },
   { 0, IPFIX_FT_MPLSVPNROUTEDISTINGUISHER, 65535, IPFIX_CODING_BYTES,
     "mplsVpnRouteDistinguisher", "" },
   { 0, IPFIX_FT_BGPNEXTADJACENTASNUMBER, 4, IPFIX_CODING_UINT,
     "bgpNextAdjacentAsNumber", "" },
   { 0, IPFIX_FT_BGPPREVADJACENTASNUMBER, 4, IPFIX_CODING_UINT,
     "bgpPrevAdjacentAsNumber", "" },
   { 0, IPFIX_FT_EXPORTERIPV4ADDRESS, 4, IPFIX_CODING_IPADDR,
     "exporterIPv4Address", "" },
   { 0, IPFIX_FT_EXPORTERIPV6ADDRESS, 16, IPFIX_CODING_IPADDR,
     "exporterIPv6Address", "" },
   { 0, IPFIX_FT_DROPPEDOCTETDELTACOUNT, 8, IPFIX_CODING_UINT,
     "droppedOctetDeltaCount", "" },
   { 0, IPFIX_FT_DROPPEDPACKETDELTACOUNT, 8, IPFIX_CODING_UINT,
     "droppedPacketDeltaCount", "" },
   { 0, IPFIX_FT_DROPPEDOCTETTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "droppedOctetTotalCount", "" },
   { 0, IPFIX_FT_DROPPEDPACKETTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "droppedPacketTotalCount", "" },
   { 0, IPFIX_FT_FLOWENDREASON, 1, IPFIX_CODING_UINT,
     "flowEndReason", "" },
   { 0, IPFIX_FT_COMMONPROPERTIESID, 8, IPFIX_CODING_UINT,
     "commonPropertiesId", "" },
   { 0, IPFIX_FT_OBSERVATIONPOINTID, 4, IPFIX_CODING_UINT,
     "observationPointId", "" },
   { 0, IPFIX_FT_ICMPTYPECODEIPV6, 2, IPFIX_CODING_UINT,
     "icmpTypeCodeIPv6", "" },
   { 0, IPFIX_FT_MPLSTOPLABELIPV6ADDRESS, 16, IPFIX_CODING_IPADDR,
     "mplsTopLabelIPv6Address", "" },
   { 0, IPFIX_FT_LINECARDID, 4, IPFIX_CODING_UINT,
     "lineCardId", "" },
   { 0, IPFIX_FT_PORTID, 4, IPFIX_CODING_UINT,
     "portId", "" },
   { 0, IPFIX_FT_METERINGPROCESSID, 4, IPFIX_CODING_UINT,
     "meteringProcessId", "" },
   { 0, IPFIX_FT_EXPORTINGPROCESSID, 4, IPFIX_CODING_UINT,
     "exportingProcessId", "" },
   { 0, IPFIX_FT_TEMPLATEID, 2, IPFIX_CODING_UINT,
     "templateId", "" },
   { 0, IPFIX_FT_WLANCHANNELID, 1, IPFIX_CODING_UINT,
     "wlanChannelId", "" },
   { 0, IPFIX_FT_WLANSSID, 65535, IPFIX_CODING_STRING,
     "wlanSSID", "" },
   { 0, IPFIX_FT_FLOWID, 8, IPFIX_CODING_UINT,
     "flowId", "" },
   { 0, IPFIX_FT_OBSERVATIONDOMAINID, 4, IPFIX_CODING_UINT,
     "observationDomainId", "" },
   { 0, IPFIX_FT_FLOWSTARTSECONDS, 4, IPFIX_CODING_UINT,
     "flowStartSeconds", "" },
   { 0, IPFIX_FT_FLOWENDSECONDS, 4, IPFIX_CODING_UINT,
     "flowEndSeconds", "" },
   { 0, IPFIX_FT_FLOWSTARTMILLISECONDS, 8, IPFIX_CODING_UINT,
     "flowStartMilliseconds", "" },
   { 0, IPFIX_FT_FLOWENDMILLISECONDS, 8, IPFIX_CODING_UINT,
     "flowEndMilliseconds", "" },
   { 0, IPFIX_FT_FLOWSTARTMICROSECONDS, 8, IPFIX_CODING_NTP,
     "flowStartMicroseconds", "" },
   { 0, IPFIX_FT_FLOWENDMICROSECONDS, 8, IPFIX_CODING_NTP,
     "flowEndMicroseconds", "" },
   { 0, IPFIX_FT_FLOWSTARTNANOSECONDS, 8, IPFIX_CODING_NTP,
     "flowStartNanoseconds", "" },
   { 0, IPFIX_FT_FLOWENDNANOSECONDS, 8, IPFIX_CODING_NTP,
     "flowEndNanoseconds", "" },
   { 0, IPFIX_FT_FLOWSTARTDELTAMICROSECONDS, 4, IPFIX_CODING_UINT,
     "flowStartDeltaMicroseconds", "" },
   { 0, IPFIX_FT_FLOWENDDELTAMICROSECONDS, 4, IPFIX_CODING_UINT,
     "flowEndDeltaMicroseconds", "" },
   { 0, IPFIX_FT_SYSTEMINITTIMEMILLISECONDS, 8, IPFIX_CODING_UINT,
     "systemInitTimeMilliseconds", "" },
   { 0, IPFIX_FT_FLOWDURATIONMILLISECONDS, 4, IPFIX_CODING_UINT,
     "flowDurationMilliseconds", "" },
   { 0, IPFIX_FT_FLOWDURATIONMICROSECONDS, 4, IPFIX_CODING_UINT,
     "flowDurationMicroseconds", "" },
   { 0, IPFIX_FT_OBSERVEDFLOWTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "observedFlowTotalCount", "" },
   { 0, IPFIX_FT_IGNOREDPACKETTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "ignoredPacketTotalCount", "" },
   { 0, IPFIX_FT_IGNOREDOCTETTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "ignoredOctetTotalCount", "" },
   { 0, IPFIX_FT_NOTSENTFLOWTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "notSentFlowTotalCount", "" },
   { 0, IPFIX_FT_NOTSENTPACKETTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "notSentPacketTotalCount", "" },
   { 0, IPFIX_FT_NOTSENTOCTETTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "notSentOctetTotalCount", "" },
   { 0, IPFIX_FT_DESTINATIONIPV6PREFIX, 16, IPFIX_CODING_IPADDR,
     "destinationIPv6Prefix", "" },
   { 0, IPFIX_FT_SOURCEIPV6PREFIX, 16, IPFIX_CODING_IPADDR,
     "sourceIPv6Prefix", "" },
   { 0, IPFIX_FT_POSTOCTETTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "postOctetTotalCount", "" },
   { 0, IPFIX_FT_POSTPACKETTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "postPacketTotalCount", "" },
   { 0, IPFIX_FT_FLOWKEYINDICATOR, 8, IPFIX_CODING_UINT,
     "flowKeyIndicator", "" },
   { 0, IPFIX_FT_POSTMCASTPACKETTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "postMCastPacketTotalCount", "" },
   { 0, IPFIX_FT_POSTMCASTOCTETTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "postMCastOctetTotalCount", "" },
   { 0, IPFIX_FT_ICMPTYPEIPV4, 1, IPFIX_CODING_UINT,
     "icmpTypeIPv4", "" },
   { 0, IPFIX_FT_ICMPCODEIPV4, 1, IPFIX_CODING_UINT,
     "icmpCodeIPv4", "" },
   { 0, IPFIX_FT_ICMPTYPEIPV6, 1, IPFIX_CODING_UINT,
     "icmpTypeIPv6", "" },
   { 0, IPFIX_FT_ICMPCODEIPV6, 1, IPFIX_CODING_UINT,
     "icmpCodeIPv6", "" },
   { 0, IPFIX_FT_UDPSOURCEPORT, 2, IPFIX_CODING_UINT,
     "udpSourcePort", "" },
   { 0, IPFIX_FT_UDPDESTINATIONPORT, 2, IPFIX_CODING_UINT,
     "udpDestinationPort", "" },
   { 0, IPFIX_FT_TCPSOURCEPORT, 2, IPFIX_CODING_UINT,
     "tcpSourcePort", "" },
   { 0, IPFIX_FT_TCPDESTINATIONPORT, 2, IPFIX_CODING_UINT,
     "tcpDestinationPort", "" },
   { 0, IPFIX_FT_TCPSEQUENCENUMBER, 4, IPFIX_CODING_UINT,
     "tcpSequenceNumber", "" },
   { 0, IPFIX_FT_TCPACKNOWLEDGEMENTNUMBER, 4, IPFIX_CODING_UINT,
     "tcpAcknowledgementNumber", "" },
   { 0, IPFIX_FT_TCPWINDOWSIZE, 2, IPFIX_CODING_UINT,
     "tcpWindowSize", "" },
   { 0, IPFIX_FT_TCPURGENTPOINTER, 2, IPFIX_CODING_UINT,
     "tcpUrgentPointer", "" },
   { 0, IPFIX_FT_TCPHEADERLENGTH, 1, IPFIX_CODING_UINT,
     "tcpHeaderLength", "" },
   { 0, IPFIX_FT_IPHEADERLENGTH, 1, IPFIX_CODING_UINT,
     "ipHeaderLength", "" },
   { 0, IPFIX_FT_TOTALLENGTHIPV4, 2, IPFIX_CODING_UINT,
     "totalLengthIPv4", "" },
   { 0, IPFIX_FT_PAYLOADLENGTHIPV6, 2, IPFIX_CODING_UINT,
     "payloadLengthIPv6", "" },
   { 0, IPFIX_FT_IPTTL, 1, IPFIX_CODING_UINT,
     "ipTTL", "" },
   { 0, IPFIX_FT_NEXTHEADERIPV6, 1, IPFIX_CODING_UINT,
     "nextHeaderIPv6", "" },
   { 0, IPFIX_FT_MPLSPAYLOADLENGTH, 4, IPFIX_CODING_UINT,
     "mplsPayloadLength", "" },
   { 0, IPFIX_FT_IPDIFFSERVCODEPOINT, 1, IPFIX_CODING_UINT,
     "ipDiffServCodePoint", "" },
   { 0, IPFIX_FT_IPPRECEDENCE, 1, IPFIX_CODING_UINT,
     "ipPrecedence", "" },
   { 0, IPFIX_FT_FRAGMENTFLAGS, 1, IPFIX_CODING_UINT,
     "fragmentFlags", "" },
   { 0, IPFIX_FT_OCTETDELTASUMOFSQUARES, 8, IPFIX_CODING_UINT,
     "octetDeltaSumOfSquares", "" },
   { 0, IPFIX_FT_OCTETTOTALSUMOFSQUARES, 8, IPFIX_CODING_UINT,
     "octetTotalSumOfSquares", "" },
   { 0, IPFIX_FT_MPLSTOPLABELTTL, 1, IPFIX_CODING_UINT,
     "mplsTopLabelTTL", "" },
   { 0, IPFIX_FT_MPLSLABELSTACKLENGTH, 4, IPFIX_CODING_UINT,
     "mplsLabelStackLength", "" },
   { 0, IPFIX_FT_MPLSLABELSTACKDEPTH, 4, IPFIX_CODING_UINT,
     "mplsLabelStackDepth", "" },
   { 0, IPFIX_FT_MPLSTOPLABELEXP, 1, IPFIX_CODING_UINT,
     "mplsTopLabelExp", "" },
   { 0, IPFIX_FT_IPPAYLOADLENGTH, 4, IPFIX_CODING_UINT,
     "ipPayloadLength", "" },
   { 0, IPFIX_FT_UDPMESSAGELENGTH, 2, IPFIX_CODING_UINT,
     "udpMessageLength", "" },
   { 0, IPFIX_FT_ISMULTICAST, 1, IPFIX_CODING_UINT,
     "isMulticast", "" },
   { 0, IPFIX_FT_IPV4IHL, 1, IPFIX_CODING_UINT,
     "ipv4IHL", "" },
   { 0, IPFIX_FT_IPV4OPTIONS, 4, IPFIX_CODING_UINT,
     "ipv4Options", "" },
   { 0, IPFIX_FT_TCPOPTIONS, 8, IPFIX_CODING_UINT,
     "tcpOptions", "" },
   { 0, IPFIX_FT_PADDINGOCTETS, 65535, IPFIX_CODING_BYTES,
     "paddingOctets", "" },
   { 0, IPFIX_FT_COLLECTORIPV4ADDRESS, 4, IPFIX_CODING_IPADDR,
     "collectorIPv4Address", "" },
   { 0, IPFIX_FT_COLLECTORIPV6ADDRESS, 16, IPFIX_CODING_IPADDR,
     "collectorIPv6Address", "" },
   { 0, IPFIX_FT_COLLECTORINTERFACE, 4, IPFIX_CODING_UINT,
     "collectorInterface", "" },
   { 0, IPFIX_FT_COLLECTORPROTOCOLVERSION, 1, IPFIX_CODING_UINT,
     "collectorProtocolVersion", "" },
   { 0, IPFIX_FT_COLLECTORTRANSPORTPROTOCOL, 1, IPFIX_CODING_UINT,
     "collectorTransportProtocol", "" },
   { 0, IPFIX_FT_COLLECTORTRANSPORTPORT, 2, IPFIX_CODING_UINT,
     "collectorTransportPort", "" },
   { 0, IPFIX_FT_EXPORTERTRANSPORTPORT, 2, IPFIX_CODING_UINT,
     "exporterTransportPort", "" },
   { 0, IPFIX_FT_TCPSYNTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "tcpSynTotalCount", "" },
   { 0, IPFIX_FT_TCPFINTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "tcpFinTotalCount", "" },
   { 0, IPFIX_FT_TCPRSTTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "tcpRstTotalCount", "" },
   { 0, IPFIX_FT_TCPPSHTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "tcpPshTotalCount", "" },
   { 0, IPFIX_FT_TCPACKTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "tcpAckTotalCount", "" },
   { 0, IPFIX_FT_TCPURGTOTALCOUNT, 8, IPFIX_CODING_UINT,
     "tcpUrgTotalCount", "" },
   { 0, IPFIX_FT_IPTOTALLENGTH, 8, IPFIX_CODING_UINT,
     "ipTotalLength", "" },
   { 0, IPFIX_FT_POSTMPLSTOPLABELEXP, 1, IPFIX_CODING_UINT,
     "postMplsTopLabelExp", "" },
   { 0, IPFIX_FT_TCPWINDOWSCALE, 2, IPFIX_CODING_UINT,
     "tcpWindowScale", "" },
   { 0, IPFIX_FT_OBSERVATIONPOINTID_PSAMP, 8, IPFIX_CODING_UINT,
     "observationPointId_PSAMP", "" },
   { 0, IPFIX_FT_SELECTIONSEQUENCEID, 8, IPFIX_CODING_UINT,
     "selectionSequenceId", "" },
   { 0, IPFIX_FT_SELECTORID, 2, IPFIX_CODING_UINT,
     "selectorId", "" },
   { 0, IPFIX_FT_INFORMATIONELEMENTID, 2, IPFIX_CODING_UINT,
     "informationElementId", "" },
   { 0, IPFIX_FT_SELECTORALGORITHM, 2, IPFIX_CODING_UINT,
     "selectorAlgorithm", "" },
   { 0, IPFIX_FT_SAMPLINGPACKETINTERVAL, 4, IPFIX_CODING_UINT,
     "samplingPacketInterval", "" },
   { 0, IPFIX_FT_SAMPLINGPACKETSPACE, 4, IPFIX_CODING_UINT,
     "samplingPacketSpace", "" },
   { 0, IPFIX_FT_SAMPLINGTIMEINTERVAL, 8, IPFIX_CODING_NTP,
     "samplingTimeInterval", "" },
   { 0, IPFIX_FT_SAMPLINGTIMESPACE, 8, IPFIX_CODING_NTP,
     "samplingTimeSpace", "" },
   { 0, IPFIX_FT_SAMPLINGSIZE, 4, IPFIX_CODING_UINT,
     "samplingSize", "" },
   { 0, IPFIX_FT_SAMPLINGPOPULATION, 4, IPFIX_CODING_UINT,
     "samplingPopulation", "" },
   { 0, IPFIX_FT_SAMPLINGPROBABILITY, 8, IPFIX_CODING_FLOAT,
     "samplingProbability", "" },
   { 0, IPFIX_FT_DATALINKFRAMESIZE, 4, IPFIX_CODING_UINT,
     "dataLinkFrameSize", "" },
   { 0, IPFIX_FT_IPHEADERPACKETSECTION, 65535, IPFIX_CODING_BYTES,
     "ipHeaderPacketSection", "" },
   { 0, IPFIX_FT_IPPAYLOADPACKETSECTION, 65535, IPFIX_CODING_BYTES,
     "ipPayloadPacketSection", "" },
   { 0, IPFIX_FT_DATALINKFRAMESECTION, 65535, IPFIX_CODING_BYTES,
     "dataLinkFrameSection", "" },
   { 0, IPFIX_FT_MPLSLABELSTACKSECTION, 65535, IPFIX_CODING_BYTES,
     "mplsLabelStackSection", "" },
   { 0, IPFIX_FT_MPLSPAYLOADPACKETSECTION, 65535, IPFIX_CODING_BYTES,
     "mplsPayloadPacketSection", "" },
   { 0, IPFIX_FT_PACKETSOBSERVED, 8, IPFIX_CODING_UINT,
     "packetsObserved", "" },
   { 0, IPFIX_FT_PACKETSSELECTED, 8, IPFIX_CODING_UINT,
     "packetsSelected", "" },
   { 0, IPFIX_FT_FIXEDERROR, 8, IPFIX_CODING_FLOAT,
     "fixedError", "" },
   { 0, IPFIX_FT_RELATIVEERROR, 8, IPFIX_CODING_FLOAT,
     "relativeError", "" },
   { 0, IPFIX_FT_OBSERVATIONTIMESECONDS, 4, IPFIX_CODING_UINT,
     "observationTimeSeconds", "" },
   { 0, IPFIX_FT_OBSERVATIONTIMEMILLISECONDS, 8, IPFIX_CODING_UINT,
     "observationTimeMilliseconds", "" },
   { 0, IPFIX_FT_OBSERVATIONTIMEMICROSECONDS, 8, IPFIX_CODING_NTP,
     "observationTimeMicroseconds", "" },
   { 0, IPFIX_FT_OBSERVATIONTIMENANOSECONDS, 8, IPFIX_CODING_NTP,
     "observationTimeNanoseconds", "" },
   { 0, IPFIX_FT_DIGESTHASHVALUE, 8, IPFIX_CODING_UINT,
     "digestHashValue", "" },
   { 0, IPFIX_FT_HASHIPPAYLOADOFFSET, 8, IPFIX_CODING_UINT,
     "hashIPPayloadOffset", "" },
   { 0, IPFIX_FT_HASHIPPAYLOADSIZE, 8, IPFIX_CODING_UINT,
     "hashIPPayloadSize", "" },
   { 0, IPFIX_FT_HASHOUTPUTRANGEMIN, 8, IPFIX_CODING_UINT,
     "hashOutputRangeMin", "" },
   { 0, IPFIX_FT_HASHOUTPUTRANGEMAX, 8, IPFIX_CODING_UINT,
     "hashOutputRangeMax", "" },
   { 0, IPFIX_FT_HASHSELECTEDRANGEMIN, 8, IPFIX_CODING_UINT,
     "hashSelectedRangeMin", "" },
   { 0, IPFIX_FT_HASHSELECTEDRANGEMAX, 8, IPFIX_CODING_UINT,
     "hashSelectedRangeMax", "" },
   { 0, IPFIX_FT_HASHDIGESTOUTPUT, 1, IPFIX_CODING_BYTES,
     "hashDigestOutput", "" },
   { 0, IPFIX_FT_HASHINITIALISERVALUE, 8, IPFIX_CODING_UINT,
     "hashInitialiserValue", "" },
   { 0, 0, -1, 0, NULL, NULL, }
};





#endif //FIELDS_H
