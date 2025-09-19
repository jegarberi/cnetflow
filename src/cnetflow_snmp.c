//
// Created by jon on 6/11/25.
//
#include "cnetflow_snmp.h"

// #include <stdlib.h>
// #include <stdio.h>
// #include <math.h>
/* change the word "define" to "undef" to try the (insecure) SNMPv1 version */
// #define DEMO_USE_SNMP_VERSION_3

#ifdef DEMO_USE_SNMP_VERSION_3
// #include "net-snmp/transform_oids.h"
const char *our_v3_passphrase = "The Net-SNMP Demo Password";
#endif

struct snmp_config {
  const char *host;
  const int port;
  const short snmp_version;
};

int snmp_test(void) {
  /*if (argc != 3){
    printf("Usage: snmp_get host community");
    return -1;
  }*/
  struct snmp_session session, *ss;
  struct snmp_pdu *pdu;
  struct snmp_pdu *response;

  oid anOID[MAX_OID_LEN];
  size_t anOID_len = MAX_OID_LEN;

  struct variable_list *vars;
  int status;
  /*
   * Initialize a "session" that defines who we're going to talk to
   */
  snmp_sess_init(&session); /* set up defaults */
  session.peername = "192.168.100.1";
  // session.peername = host;
  /* set up the authentication parameters for talking to the server */

#ifdef DEMO_USE_SNMP_VERSION_3

  /* Use SNMPv3 to talk to the experimental server */

  /* set the SNMP version number */
  session.version = SNMP_VERSION_3;

  /* set the SNMPv3 user name */
  session.securityName = strdup("MD5User");
  session.securityNameLen = strlen(session.securityName);

  /* set the security level to authenticated, but not encrypted */
  session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;

  /* set the authentication method to MD5 */
  session.securityAuthProto = usmHMACMD5AuthProtocol;
  session.securityAuthProtoLen = sizeof(usmHMACMD5AuthProtocol) / sizeof(oid);
  session.securityAuthKeyLen = USM_AUTH_KU_LEN;

  /* set the authentication key to a MD5 hashed version of our
      passphrase "The Net-SNMP Demo Password" (which must be at least 8
      characters long) */
  if (generate_Ku(session.securityAuthProto, session.securityAuthProtoLen, (u_char *) our_v3_passphrase,
                  strlen(our_v3_passphrase), session.securityAuthKey, &session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
    // snmp_perror();
    snmp_log(LOG_ERR, "Error generating Ku from authentication pass phrase. \n");
    exit(1);
  }

#else /* we'll use the insecure (but simpler) SNMPv1 */

  /* set the SNMP version number */
  session.version = SNMP_VERSION_1;

  /* set the SNMPv1 community name used for authentication */
  session.community = "rccg";
  // session.community = comm;
  session.community_len = strlen(session.community);

#endif
/* SNMPv1 */
  /* windows32 specific initialization (is a noop on unix) */
  SOCK_STARTUP;

  /*
   * Open the session
   */
  ss = snmp_open(&session); /* establish the session */
  if (!ss) {
    snmp_perror("ack");
    snmp_log(LOG_ERR, "something horrible happened!!!\n");
    exit(2);
  }
  /*
   * Create the PDU for the data for our request.
   *   1) We're going to GET the system.sysDescr.0 node.
   */
  pdu = snmp_pdu_create(SNMP_MSG_GET);
  read_objid(".1.3.6.1.2.1.1.1.0", anOID, &anOID_len);

#if OTHER_METHODS
  get_node("sysDescr.0", anOID, &anOID_len);
  read_objid("system.sysDescr.0", anOID, &anOID_len);
#endif
  snmp_add_null_var(pdu, anOID, anOID_len);
  /*
   * Send the Request out.
   */
  status = snmp_synch_response(ss, pdu, &response);
  /*
   * Process the response.
   */
  if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
    /*
     * SUCCESS: Print the result variables
     */
    for (vars = response->variables; vars; vars = vars->next_variable)
      print_variable(vars->name, vars->name_length, vars);
    /* manipulate the information ourselves */
    for (vars = response->variables; vars; vars = vars->next_variable) {
      int count = 1;
      if (vars->type == ASN_OCTET_STR) {
        char *sp = malloc(1 + vars->val_len);
        memcpy(sp, vars->val.string, vars->val_len);
        sp[vars->val_len] = '\0';
        printf("value #%d is a string: %s\n", count++, sp);
        free(sp);
      } else
        printf("value #%d is NOT a string! Ack!\n", count++);
    }
  } else {
    /*
     * FAILURE: print what went wrong!
     */

    if (status == STAT_SUCCESS)
      fprintf(stderr, "Error in packet\nReason: %s\n", snmp_errstring(response->errstat));
    else
      snmp_sess_perror("snmpget", ss);
  }
  /*
   * Clean up:
   *  1) free the response.
   *  2) close the session.
   */
  if (response) {
    snmp_free_pdu(response);
  }

  snmp_close(ss);

  /* windows32 specific cleanup (is a noop on unix) */
  SOCK_CLEANUP;
  return 0;
} /* main() */
