//
// Created by jon on 6/3/25.
//
#include "netflow_v5.h"
#include <stdlib.h>
#include <string.h>

#include "arena.h"
#include "collector.h"

arena_struct_t *arena_collector;


/**
 * Parses and processes NetFlow v5 data from the provided arguments structure,
 * updating flow timestamps, swapping endianness where necessary, and inserting
 * the parsed records into a database. This function also manages concurrency
 * using a mutex lock during processing.
 *
 * @param args_data   A pointer to a `parse_args_t` structure containing NetFlow
 *                    v5 data to be parsed and processed. Must include a valid
 *                    data buffer and mutex for synchronization.
 * @return            A pointer to result or data processed (depends on the
 *                    function usage; typically NULL if no return object is needed).
 */
void *parse_v5(uv_work_t *req) {
  parse_args_t *args = (parse_args_t *) req->data;
  args->status = collector_data_status_processing;
  netflow_v5_flowset_t *netflow_packet_ptr;
  netflow_packet_ptr = (netflow_v5_flowset_t *) args->data;


  swap_endianness((void *) &(netflow_packet_ptr->header.version), sizeof(netflow_packet_ptr->header.version));
  if (netflow_packet_ptr->header.version != 5) {
    fprintf(stderr, "%s %d %s This should not happen...\n", __FILE__, __LINE__, __func__);
    exit(-1);
    goto unlock_mutex_parse_v5;
  }
  swap_endianness((void *) &(netflow_packet_ptr->header.count), sizeof(netflow_packet_ptr->header.count));
  if (netflow_packet_ptr->header.count > 30) {
    fprintf(stderr, "Too many flows...\n");
    goto unlock_mutex_parse_v5;
  }
  swap_endianness((void *) &(netflow_packet_ptr->header.SysUptime), sizeof(netflow_packet_ptr->header.SysUptime));
  swap_endianness((void *) &(netflow_packet_ptr->header.unix_secs), sizeof(netflow_packet_ptr->header.unix_secs));
  swap_endianness((void *) &(netflow_packet_ptr->header.unix_nsecs), sizeof(netflow_packet_ptr->header.unix_nsecs));
  swap_endianness((void *) &(netflow_packet_ptr->header.flow_sequence),
                  sizeof(netflow_packet_ptr->header.flow_sequence));
  swap_endianness((void *) &(netflow_packet_ptr->header.sampling_interval),
                  sizeof(netflow_packet_ptr->header.sampling_interval));

  uint32_t now = (uint32_t) time(NULL);
  uint32_t diff = now - (uint32_t) (netflow_packet_ptr->header.SysUptime / 1000);

  // memcpy(records, args->data + sizeof(netflow_v5_header_t), args->len - (sizeof(netflow_v5_header_t)));
  // memcpy(&netflow_packet_ptr, args->data, args->len);
  for (int i = 0; i < netflow_packet_ptr->header.count; i++) {
    /*
    swap_endianness((void*)&(records[i].srcaddr), sizeof((records[i].srcaddr)));
    swap_endianness((void*)&(records[i].dstaddr), sizeof((records[i].dstaddr)));
    swap_endianness((void *) &(records[i].nexthop), sizeof((records[i].nexthop)));
    swap_endianness((void *) &(records[i].input), sizeof((records[i].input)));
    swap_endianness((void *) &(records[i].output), sizeof((records[i].output)));
    swap_endianness((void *) &(records[i].dPkts), sizeof((records[i].dPkts)));
    swap_endianness((void *) &(records[i].dOctets), sizeof((records[i].dOctets)));
    */
    swap_endianness((void *) &(netflow_packet_ptr->records[i].First), sizeof((netflow_packet_ptr->records[i].First)));
    swap_endianness((void *) &(netflow_packet_ptr->records[i].Last), sizeof((netflow_packet_ptr->records[i].Last)));
    netflow_packet_ptr->records[i].First = netflow_packet_ptr->records[i].First / 1000 + diff;
    netflow_packet_ptr->records[i].Last = netflow_packet_ptr->records[i].Last / 1000 + diff;
    swap_endianness((void *) &(netflow_packet_ptr->records[i].First), sizeof((netflow_packet_ptr->records[i].First)));
    swap_endianness((void *) &(netflow_packet_ptr->records[i].Last), sizeof((netflow_packet_ptr->records[i].Last)));
    /*
    swap_endianness((void *) &(records[i].srcport), sizeof((records[i].srcport)));
    swap_endianness((void *) &(records[i].dstport), sizeof((records[i].dstport)));
    // pad1
    // tcp_flags
    // prot
    // tos
    swap_endianness((void *) &(records[i].src_as), sizeof((records[i].src_as)));
    swap_endianness((void *) &(records[i].dst_as), sizeof((records[i].dst_as)));
    swap_endianness((void *) &(records[i].src_mask), sizeof((records[i].src_mask)));
    swap_endianness((void *) &(records[i].dst_mask), sizeof((records[i].dst_mask)));
    */
    swap_endianness((void *) &(netflow_packet_ptr->records[i].srcport),
                    sizeof((netflow_packet_ptr->records[i].srcport)));
    swap_endianness((void *) &(netflow_packet_ptr->records[i].dstport),
                    sizeof((netflow_packet_ptr->records[i].dstport)));

    swap_src_dst_v5(&netflow_packet_ptr->records[i]);


    swap_endianness((void *) &(netflow_packet_ptr->records[i].srcport),
                    sizeof((netflow_packet_ptr->records[i].srcport)));
    swap_endianness((void *) &(netflow_packet_ptr->records[i].dstport),
                    sizeof((netflow_packet_ptr->records[i].dstport)));
#ifdef CNETFLOW_DEBUG_BUILD
    printf_v5(stdout, netflow_packet_ptr, i);
#endif
  }
  // swap_endianness((void *) &args->exporter, sizeof(args->exporter));
  insert_v5(args->exporter, netflow_packet_ptr);

  netflow_v9_uint128_flowset_t flows_to_insert = {0};
  copy_v5_to_flow(netflow_packet_ptr, &flows_to_insert);
  insert_flows(args->exporter, &flows_to_insert);

unlock_mutex_parse_v5:
  // uv_mutex_unlock(lock);
  args->status = collector_data_status_done;

  return NULL;
}


void copy_v5_to_flow(netflow_v5_flowset_t *in, netflow_v9_uint128_flowset_t *out) {
  out->header.count = in->header.count;
  out->header.SysUptime = in->header.SysUptime;
  out->header.unix_secs = in->header.unix_secs;
  out->header.unix_nsecs = in->header.unix_nsecs;
  out->header.flow_sequence = in->header.flow_sequence;
  out->header.sampling_interval = in->header.sampling_interval;
  for (int i = 0; i < in->header.count; i++) {
    out->records[i].srcaddr = in->records[i].srcaddr;
    out->records[i].dstaddr = in->records[i].dstaddr;
    out->records[i].nexthop = in->records[i].nexthop;
    out->records[i].input = in->records[i].input;
    out->records[i].output = in->records[i].output;
    out->records[i].dPkts = in->records[i].dPkts;
    out->records[i].dOctets = in->records[i].dOctets;
    out->records[i].First = in->records[i].First;
    out->records[i].Last = in->records[i].Last;
    out->records[i].srcport = in->records[i].srcport;
    out->records[i].dstport = in->records[i].dstport;
    out->records[i].src_as = in->records[i].src_as;
    out->records[i].dst_as = in->records[i].dst_as;
    out->records[i].src_mask = in->records[i].src_mask;
    out->records[i].dst_mask = in->records[i].dst_mask;
    out->records[i].tcp_flags = in->records[i].tcp_flags;
    out->records[i].prot = in->records[i].prot;
    out->records[i].tos = in->records[i].tos;
    out->records[i].ip_version = 4;
  }
}
