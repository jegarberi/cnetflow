//
// Created by jon on 6/11/25.
//

#ifndef CNETFLOW_SNMP_H
#define CNETFLOW_SNMP_H
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stdint.h>
#define SYSDESCR ".1.3.6.1.2.1.1.1.0"
#define SYSNAME ".1.3.6.1.2.1.1.5.0"
#define IFDESCR ".1.3.6.1.2.1.2.2.1.2"
#define IFALIAS ".1.3.6.1.2.1.31.1.1.1.18"
#define IFTYPE ".1.3.6.1.2.1.2.2.1.3"
#define IFSPEED ".1.3.6.1.2.1.2.2.1.5"
#define IFPHYSADDRESS ".1.3.6.1.2.1.2.2.1.6"
#define IFADMINSTATUS ".1.3.6.1.2.1.2.2.1.7"
#define IFOPERSTATUS ".1.3.6.1.2.1.2.2.1.8"
#define IFINOCTETS ".1.3.6.1.2.1.2.2.1.10"
#define IFINUCASTPKTS ".1.3.6.1.2.1.2.2.1.11"
#define IFINNUCASTPKTS ".1.3.6.1.2.1.2.2.1.12"
#define IFINDISCARDS ".1.3.6.1.2.1.2.2.1.13"
#define IFINERRORS ".1.3.6.1.2.1.2.2.1.14"
#define IFOUTOCTETS ".1.3.6.1.2.1.2.2.1.16"
#define IFOUTUCASTPKTS ".1.3.6.1.2.1.2.2.1.17"

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

int snmp_test(void);
int poll_exporter(const char *host, int snmp_version, char *community, char *user, int security_level, int auth_proto,
                  char *auth_pass, int priv_proto, char *priv_pass);

int poll_interface(const char *host, int snmp_version, char *community, char *user, int security_level, int auth_proto);
#endif // CNETFLOW_SNMP_H
