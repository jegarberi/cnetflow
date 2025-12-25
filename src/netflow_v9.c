//
// Created by jon on 6/3/25.
//


#include "netflow_v9.h"
#include <assert.h>
#include <stdio.h>
#include "netflow_v5.h"
#include "db.h"
#include "log.h"
static hashmap_t *templates_nfv9_hashmap;
extern arena_struct_t *arena_collector;
extern arena_struct_t *arena_hashmap_nf9;

void init_v9(arena_struct_t *arena, const size_t cap) {
  LOG_ERROR("%s %d %s: Initializing v9 [templates_nfv9_hashmap]...\n", __FILE__, __LINE__, __func__);
  templates_nfv9_hashmap = hashmap_create(arena, cap);
}

void *parse_v9(uv_work_t *req) {
  parse_args_t *args = (parse_args_t *) req->data;
  args->status = collector_data_status_processing;

  if (args->len < sizeof(netflow_v9_header_t)) {
    goto unlock_mutex_parse_v9;
  }

  netflow_v9_header_t *header = (netflow_v9_header_t *) (args->data);

  uint16_t version = header->version;
  swap_endianness(&version, sizeof(version));
  if (version != 9) {
    goto unlock_mutex_parse_v9;
  }

  uint16_t count = header->count;
  swap_endianness(&count, sizeof(count));
  if (count > 30000) {
    LOG_ERROR("%s %d %s: Too many flows\n", __FILE__, __LINE__, __func__);
    goto unlock_mutex_parse_v9;
  }

  uint32_t sys_uptime = header->SysUptime;
  swap_endianness(&sys_uptime, sizeof(sys_uptime));

  uint32_t now = (uint32_t) time(NULL);
  uint32_t diff = now - (uint32_t) (sys_uptime / 1000);

  size_t total_records = count;
  size_t processed_records = 0;
  size_t offset = sizeof(netflow_v9_header_t);
  size_t total_packet_length = args->len;

  LOG_ERROR("%s %d %s: total records to process: %lu, packet len: %lu\n",
            __FILE__, __LINE__, __func__, total_records, total_packet_length);

  while (offset + 4 <= total_packet_length && processed_records < total_records) {
    uint16_t flowset_id;
    uint16_t flowset_length;

    memcpy(&flowset_id, args->data + offset, 2);
    memcpy(&flowset_length, args->data + offset + 2, 2);
    swap_endianness(&flowset_id, sizeof(flowset_id));
    swap_endianness(&flowset_length, sizeof(flowset_length));

    if (flowset_length < 4 || offset + flowset_length > total_packet_length) {
      LOG_ERROR("%s %d %s: Invalid flowset length: %u at offset %lu\n",
                __FILE__, __LINE__, __func__, flowset_length, offset);
      break;
    }

    LOG_ERROR("%s %d %s: flowset_id: %u, length: %u at offset %lu\n",
              __FILE__, __LINE__, __func__, flowset_id, flowset_length, offset);

    if (flowset_id == 0) {
      // Template FlowSet
      size_t pos = 4; // Skip FlowSet ID and Length
      while (pos + 4 <= flowset_length && processed_records < total_records) {
        netflow_v9_template_t *template = (netflow_v9_template_t *)(args->data + offset + pos);
        uint16_t template_id = template->template_id;
        uint16_t field_count = template->field_count;
        swap_endianness(&template_id, sizeof(template_id));
        swap_endianness(&field_count, sizeof(field_count));

        if (template_id < 256) {
           // Reserved template IDs? RFC says 0-255 are reserved for FlowSet IDs.
           // Templates for data records start at 256.
        }

        LOG_ERROR("%s %d %s template_id: %u field count: %u\n", __FILE__, __LINE__, __func__, template_id, field_count);

        if (pos + 4 + field_count * 4 > flowset_length) {
            LOG_ERROR("%s %d %s: Template too large for flowset\n", __FILE__, __LINE__, __func__);
            break;
        }

        // Store template in hashmap
        char key[255];
        snprintf(key, 255, "%s-%u", ip_int_to_str(args->exporter), template_id);
        uint16_t *template_hashmap = (uint16_t *) hashmap_get(templates_nfv9_hashmap, key, strlen(key));

        size_t copy_size = 4 + field_count * 4;
        if (template_hashmap == NULL) {
            uint16_t *temp = arena_alloc(arena_hashmap_nf9, copy_size);
            if (temp) {
                memcpy(temp, args->data + offset + pos, copy_size);
                hashmap_set(templates_nfv9_hashmap, arena_hashmap_nf9, key, strlen(key), temp);
            }
        } else {
            // Update existing template? RFC doesn't say templates are immutable.
            // But we should probably check if the size changed.
            // For now, let's just keep it.
        }

        pos += copy_size;
        processed_records++;
      }
    } else if (flowset_id >= 256) {
      // Data FlowSet
      uint16_t template_id = flowset_id;
      char key[255];
      snprintf(key, 255, "%s-%u", ip_int_to_str(args->exporter), template_id);
      uint16_t *template_data = (uint16_t *) hashmap_get(templates_nfv9_hashmap, key, strlen(key));

      if (template_data == NULL) {
        LOG_ERROR("%s %d %s: template %u not found for exporter %s\n",
                  __FILE__, __LINE__, __func__, template_id, ip_int_to_str(args->exporter));
      } else {
        uint16_t field_count = template_data[1];
        swap_endianness(&field_count, sizeof(field_count));

        size_t record_len = 0;
        for (int i = 0; i < field_count; i++) {
          uint16_t record_length = template_data[2 + i * 2 + 1];
          swap_endianness(&record_length, sizeof(record_length));
          record_len += record_length;
        }

        if (record_len == 0) {
           LOG_ERROR("%s %d %s: template %u has 0 length records\n", __FILE__, __LINE__, __func__, template_id);
        } else {
            size_t pos = 4;
            size_t record_counter = 0;
            netflow_v9_flowset_t netflow_packet = {0};
            netflow_v9_flowset_t *netflow_packet_ptr = &netflow_packet;
            int is_ipv6 = 0;

            while (pos + record_len <= flowset_length && processed_records < total_records) {
              // Initialize this record to zero
              netflow_v9_record_insert_t empty_record = {0};
              memcpy(&netflow_packet.records[record_counter], &empty_record, sizeof(netflow_v9_record_insert_t));

              void *record_ptr = args->data + offset + pos;
              size_t field_offset = 0;
              for (int i = 0; i < field_count; i++) {
                uint16_t f_type = template_data[2 + i * 2];
                uint16_t record_length = template_data[2 + i * 2 + 1];
                swap_endianness(&f_type, sizeof(f_type));
                swap_endianness(&record_length, sizeof(record_length));

                void *field_ptr = record_ptr + field_offset;

                // Decode fields (similar to original logic)
                uint8_t *tmp8 = (uint8_t *)field_ptr;
                uint8_t val_tmp8 = 0;
                uint16_t *tmp16 = (uint16_t *)field_ptr;
                uint16_t val_tmp16 = 0;
                uint32_t *tmp32 = (uint32_t *)field_ptr;
                uint32_t val_tmp32 = 0;
                uint64_t *tmp64 = (uint64_t *)field_ptr;
                uint64_t val_tmp64 = 0;
                uint128_t *tmp128 = (uint128_t *)field_ptr;
                uint128_t val_tmp128;

                // Read values into local variables for consistent handling
                switch (record_length) {
                  case 1:
                    val_tmp8 = *tmp8;
                    break;
                  case 2:
                    val_tmp16 = *tmp16;
                    break;
                  case 4:
                    val_tmp32 = *tmp32;
                    break;
                  case 6:
                    val_tmp64 = *tmp64;
                    val_tmp64 &= 0x0000ffffffffffff;
                    val_tmp64 = val_tmp64 >> 16;
                    break;
                  case 8:
                    val_tmp64 = *tmp64;
                    break;
                  case 16:
                    memcpy(&val_tmp128, field_ptr, 16);
                    break;
                }

                switch (f_type) {
                  case IPFIX_FT_FLOWENDSYSUPTIME:
                    if (record_length == 4) {
                      swap_endianness(&val_tmp32, sizeof(val_tmp32));
                      val_tmp32 = val_tmp32 / 1000 + diff;
                      swap_endianness(&val_tmp32, sizeof(val_tmp32));
                      netflow_packet_ptr->records[record_counter].Last = val_tmp32;
                    } else if (record_length == 8) {
                      swap_endianness(&val_tmp64, sizeof(val_tmp64));
                      val_tmp64 = val_tmp64 / 1000 + diff;
                      swap_endianness(&val_tmp64, sizeof(val_tmp64));
                      netflow_packet_ptr->records[record_counter].Last = (uint32_t) (val_tmp128 >> 32);
                    }else {
                      netflow_packet_ptr->records[record_counter].Last = 0;
                    }
                  case IPFIX_FT_IPVERSION:
                    netflow_packet_ptr->records[record_counter].ip_version = val_tmp8;
                    if (val_tmp8 == 6) is_ipv6 = 1;
                    break;
                  case IPFIX_FT_SOURCEIPV4ADDRESS:
                    if (record_length == 4) netflow_packet_ptr->records[record_counter].srcaddr = val_tmp32;
                    netflow_packet_ptr->records[record_counter].ip_version = 4;
                    break;
                  case IPFIX_FT_DESTINATIONIPV4ADDRESS:
                    if (record_length == 4) netflow_packet_ptr->records[record_counter].dstaddr = val_tmp32;
                    break;
                  case IPFIX_FT_SOURCEIPV6ADDRESS:
                    if (record_length == 16) {
                        netflow_packet_ptr->records[record_counter].ipv6srcaddr = val_tmp128;
                        netflow_packet_ptr->records[record_counter].ip_version = 6;
                        is_ipv6 = 1;
                    }
                    break;
                  case IPFIX_FT_DESTINATIONIPV6ADDRESS:
                    if (record_length == 16) {
                        netflow_packet_ptr->records[record_counter].ipv6dstaddr = val_tmp128;
                        is_ipv6 = 1;
                    }
                    break;
                  case IPFIX_FT_BGPNEXTHOPIPV6ADDRESS:
                    if (record_length == 16) {
                        netflow_packet_ptr->records[record_counter].ipv6nexthop = val_tmp128;
                        is_ipv6 = 1;
                    }
                    break;
                  case IPFIX_FT_OCTETDELTACOUNT:
                    if (record_length == 4) {
                        netflow_packet_ptr->records[record_counter].dOctets = (uint64_t)val_tmp32;
                    }
                    else if (record_length == 8) {
                        netflow_packet_ptr->records[record_counter].dOctets = val_tmp64;
                    }
                    break;
                  case IPFIX_FT_PACKETDELTACOUNT:
                    if (record_length == 4) {
                        netflow_packet_ptr->records[record_counter].dPkts = (uint64_t)val_tmp32;
                    }
                    else if (record_length == 8) {
                        netflow_packet_ptr->records[record_counter].dPkts = val_tmp64;
                    }

                    break;
                  case IPFIX_FT_DESTINATIONTRANSPORTPORT:
                    if (record_length == 2) netflow_packet_ptr->records[record_counter].dstport = val_tmp16;
                    break;
                  case IPFIX_FT_SOURCETRANSPORTPORT:
                    if (record_length == 2) netflow_packet_ptr->records[record_counter].srcport = val_tmp16;
                    break;
                  case IPFIX_FT_PROTOCOLIDENTIFIER:
                    netflow_packet_ptr->records[record_counter].prot = val_tmp8;
                    break;
                  case IPFIX_FT_TCPCONTROLBITS:
                    netflow_packet_ptr->records[record_counter].tcp_flags = val_tmp8;
                    break;
                  case IPFIX_FT_IPCLASSOFSERVICE:
                    netflow_packet_ptr->records[record_counter].tos = val_tmp8;
                    break;
                  case IPFIX_FT_INGRESSINTERFACE:
                    if (record_length == 2) netflow_packet_ptr->records[record_counter].input = val_tmp16;
                    else if (record_length == 4) {
                        netflow_packet_ptr->records[record_counter].input = (uint16_t)(val_tmp32 >> 16);
                    }
                    break;
                  case IPFIX_FT_EGRESSINTERFACE:
                    if (record_length == 2) netflow_packet_ptr->records[record_counter].output = val_tmp16;
                    else if (record_length == 4) {
                        netflow_packet_ptr->records[record_counter].output = (uint16_t)(val_tmp32 >> 16);
                    }
                    break;
                  case IPFIX_FT_BGPSOURCEASNUMBER:
                    if (record_length == 2) {
                        netflow_packet_ptr->records[record_counter].src_as = (uint32_t)val_tmp16;
                    }
                    else if (record_length == 4) {
                        netflow_packet_ptr->records[record_counter].src_as = val_tmp32;
                    }
                    break;
                  case IPFIX_FT_BGPDESTINATIONASNUMBER:
                    if (record_length == 2) {
                        netflow_packet_ptr->records[record_counter].dst_as = (uint32_t)val_tmp16;
                    }
                    else if (record_length == 4) {
                        netflow_packet_ptr->records[record_counter].dst_as = val_tmp32;
                    }
                    break;
                  case IPFIX_FT_BGPNEXTHOPIPV4ADDRESS:
                    if (record_length == 4) netflow_packet_ptr->records[record_counter].nexthop = val_tmp32;
                    break;
                  case IPFIX_FT_SOURCEIPV4PREFIXLENGTH:
                  case IPFIX_FT_SOURCEIPV6PREFIXLENGTH:
                    netflow_packet_ptr->records[record_counter].src_mask = val_tmp8;
                    break;
                  case IPFIX_FT_DESTINATIONIPV4PREFIXLENGTH:
                  case IPFIX_FT_DESTINATIONIPV6PREFIXLENGTH:
                    netflow_packet_ptr->records[record_counter].dst_mask = val_tmp8;
                    break;
                }
                field_offset += record_length;
              }

              // Finalize record
              // Original logic for duration and timestamps
              if (netflow_packet_ptr->records[record_counter].Last != 0 && netflow_packet_ptr->records[record_counter].First != 0) {
                // Duration calculation in host order
                uint32_t first = netflow_packet_ptr->records[record_counter].First;
                uint32_t last = netflow_packet_ptr->records[record_counter].Last;
                // Since they were already converted to host order (val / 1000 + diff), we use them directly
                uint32_t duration = last - first;
                netflow_packet_ptr->records[record_counter].Last = now;
                netflow_packet_ptr->records[record_counter].First = now - duration;

                // Original code was swapping them back to network order here?
                // Let's check copy_v9_to_flow. It swaps them.
                // So if we want them to be host order after copy_v9_to_flow,
                // and copy_v9_to_flow DOES a swap, then we should provide them in NETWORK order.
                swap_endianness(&netflow_packet_ptr->records[record_counter].Last, 4);
                swap_endianness(&netflow_packet_ptr->records[record_counter].First, 4);
              }

              if (!is_ipv6) {
                  // Original code was swapping these before and after swap_src_dst
                  swap_endianness(&netflow_packet_ptr->records[record_counter].srcport, sizeof(netflow_packet_ptr->records[record_counter].srcport));
                  swap_endianness(&netflow_packet_ptr->records[record_counter].dstport, sizeof(netflow_packet_ptr->records[record_counter].dstport));
                  swap_endianness(&netflow_packet_ptr->records[record_counter].srcaddr, sizeof(netflow_packet_ptr->records[record_counter].srcaddr));
                  swap_endianness(&netflow_packet_ptr->records[record_counter].dstaddr, sizeof(netflow_packet_ptr->records[record_counter].dstaddr));

                  swap_src_dst_v9_ipv4(&netflow_packet_ptr->records[record_counter]);

                  swap_endianness(&netflow_packet_ptr->records[record_counter].srcport, sizeof(netflow_packet_ptr->records[record_counter].srcport));
                  swap_endianness(&netflow_packet_ptr->records[record_counter].dstport, sizeof(netflow_packet_ptr->records[record_counter].dstport));
                  swap_endianness(&netflow_packet_ptr->records[record_counter].srcaddr, sizeof(netflow_packet_ptr->records[record_counter].srcaddr));
                  swap_endianness(&netflow_packet_ptr->records[record_counter].dstaddr, sizeof(netflow_packet_ptr->records[record_counter].dstaddr));
              }

              pos += record_len;
              record_counter++;
              processed_records++;
            }

            // Insert all records in this flowset as a batch
            if (record_counter > 0) {
              netflow_packet_ptr->header.count = record_counter;
              netflow_v9_uint128_flowset_t flows_to_insert = {0};
              copy_v9_to_flow(netflow_packet_ptr, &flows_to_insert, is_ipv6);

              uint32_t exporter_host = args->exporter;
              swap_endianness(&exporter_host, sizeof(exporter_host));
              insert_flows(exporter_host, &flows_to_insert);
            }
        }
      }
    }

    offset += flowset_length;
    // Align to 4 bytes
    offset = (offset + 3) & ~3;
  }

unlock_mutex_parse_v9:
  args->status = collector_data_status_done;
  return NULL;
}


void copy_v9_to_flow(netflow_v9_flowset_t *in, netflow_v9_uint128_flowset_t *out, int is_ipv6) {
  //fprintf(stderr, "%s %d %s copy_v9_to_flow entry\n", __FILE__, __LINE__, __func__);
  out->header.count = in->header.count;
  out->header.SysUptime = in->header.SysUptime;
  out->header.unix_secs = in->header.unix_secs;
  out->header.unix_nsecs = in->header.unix_nsecs;
  out->header.flow_sequence = in->header.flow_sequence;
  out->header.sampling_interval = in->header.sampling_interval;
  for (int i = 0; i < in->header.count; i++) {
    //LOG_ERROR("%s %d %s copy_v9_to_flow loop\n", __FILE__, __LINE__, __func__);
    if (in->records[i].dOctets == 0) {
      LOG_ERROR("%s %d %s dOctets is 0\n", __FILE__, __LINE__, __func__);
      continue;
    }
    if (in->records[i].dPkts == 0) {
      LOG_ERROR("%s %d %s dPkts is 0\n", __FILE__, __LINE__, __func__);
      continue;
    }
    swap_endianness(&in->records[i].srcaddr, sizeof(in->records[i].srcaddr));
    swap_endianness(&in->records[i].dstaddr, sizeof(in->records[i].dstaddr));
    swap_endianness(&in->records[i].nexthop, sizeof(in->records[i].nexthop));
    swap_endianness(&in->records[i].ipv6srcaddr, sizeof(in->records[i].ipv6srcaddr));
    swap_endianness(&in->records[i].ipv6dstaddr, sizeof(in->records[i].ipv6dstaddr));
    swap_endianness(&in->records[i].ipv6nexthop, sizeof(in->records[i].ipv6nexthop));
    swap_endianness(&in->records[i].srcport, sizeof(in->records[i].srcport));
    swap_endianness(&in->records[i].dstport, sizeof(in->records[i].dstport));
    swap_endianness(&in->records[i].dPkts, sizeof(in->records[i].dPkts));
    swap_endianness(&in->records[i].dOctets, sizeof(in->records[i].dOctets));
    swap_endianness(&in->records[i].First, sizeof(in->records[i].First));
    swap_endianness(&in->records[i].Last, sizeof(in->records[i].Last));
    swap_endianness(&in->records[i].input, sizeof(in->records[i].input));
    swap_endianness(&in->records[i].output, sizeof(in->records[i].output));
    swap_endianness(&in->records[i].src_as, sizeof(in->records[i].src_as));
    swap_endianness(&in->records[i].dst_as, sizeof(in->records[i].dst_as));
    swap_endianness(&in->records[i].src_mask, sizeof(in->records[i].src_mask));
    swap_endianness(&in->records[i].dst_mask, sizeof(in->records[i].dst_mask));
    if (is_ipv6) {
      out->records[i].dstaddr = in->records[i].ipv6dstaddr;
      out->records[i].srcaddr = in->records[i].ipv6srcaddr;
      out->records[i].nexthop = in->records[i].ipv6nexthop;
    } else {
      out->records[i].dstaddr = in->records[i].dstaddr;
      out->records[i].srcaddr = in->records[i].srcaddr;
      out->records[i].nexthop = in->records[i].nexthop;
    }
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
    if (is_ipv6) {
      out->records[i].ip_version = 6;
    } else {
      out->records[i].ip_version = 4;
    }
  }
  //fprintf(stderr, "%s %d %s copy_v9_to_flow return\n", __FILE__, __LINE__, __func__);
}
