//
// Created by jon on 6/11/25.
//

#ifndef SNMP_H
#define SNMP_H
#include <stdint.h>

typedef struct {
  uint32_t exporter;
  uint16_t ifIndex;
  char ifDescr[100];
  char ifAlias[100];
  char ifType[100];
  char ifSpeed[100];
  char ifPhysAddress[100];
  char ifAdminStatus[100];
  char ifOperStatus[100];
  uint64_t ifInOctets;
  uint64_t ifInUcastPkts;
  uint64_t ifInNUcastPkts;
  uint64_t ifInDiscards;
  uint64_t ifInErrors;
  uint64_t ifOutOctets;
  uint64_t ifOutUcastPkts;
} interface_t;
#endif //SNMP_H
