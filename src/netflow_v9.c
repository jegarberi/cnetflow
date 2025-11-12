//
// Created by jon on 6/3/25.
//


#include "netflow_v9.h"
#include <assert.h>
#include <stdio.h>
#include "netflow_v5.h"
static hashmap_t *templates_nfv9_hashmap;
extern arena_struct_t *arena_collector;
extern arena_struct_t *arena_hashmap_nf9;

void init_v9(arena_struct_t *arena, const size_t cap) {
  fprintf(stderr, "%s %d %s: Initializing v9 [templates_nfv9_hashmap]...\n", __FILE__, __LINE__, __func__);
  templates_nfv9_hashmap = hashmap_create(arena, cap);
}

void *parse_v9(uv_work_t *req) {

  parse_args_t *args = (parse_args_t *) req->data;
  args->status = collector_data_status_processing;
  //__attribute__((cleanup(uv_mutex_unlock))) uv_mutex_t * lock = &(args->mutex);
  netflow_v9_header_t *header = (netflow_v9_header_t *) (args->data);

  swap_endianness((void *) &(header->version), sizeof(header->version));
  if (header->version != 9) {
    goto unlock_mutex_parse_v9;
  }
  swap_endianness((void *) &(header->count), sizeof(header->count));
  if (header->count > 30000) {
    fprintf(stderr, "%s %d %s: Too many flows\n", __FILE__, __LINE__, __func__);
    goto unlock_mutex_parse_v9;
  }
  size_t flowsets = header->count;
  fprintf(stderr, "%s %d %s: flowsets in data: %d\n", __FILE__, __LINE__, __func__, header->count);
  swap_endianness((void *) &(header->SysUptime), sizeof(header->SysUptime));
  swap_endianness((void *) &(header->unix_secs), sizeof(header->unix_secs));
  swap_endianness((void *) &(header->package_sequence), sizeof(header->package_sequence));
  swap_endianness((void *) &(header->source_id), sizeof(header->source_id));

  uint32_t now = (uint32_t) time(NULL);
  uint32_t diff = now - (uint32_t) (header->SysUptime / 1000);

  flowset_union_t *flowset;

  size_t flowset_counter = 0;
  size_t record_counter = 0;
  size_t template_counter = 0;
  size_t flowset_base = 0;
  size_t flowset_end = 0;
  size_t total_flowsets = 0;
  uint16_t len = 0;
  size_t total_packet_length = args->len;
  fprintf(stderr, "%s %d %s: args->len: %lu\n", __FILE__, __LINE__, __func__, total_packet_length);

  for (flowset_counter = 0; flowset_counter < flowsets; ++flowset_counter) {
    if (flowset_counter == 0) {
      flowset_base = sizeof(netflow_v9_header_t);
      flowset = (flowset_union_t *) (args->data + flowset_base);
      len = flowset->record.length;
      swap_endianness(&len, sizeof(len));
      flowset_end = flowset_base + len;
      // swap_endianness(&flowset_base,sizeof(flowset_base));

    } else {
      flowset_base = flowset_end;
      flowset = (flowset_union_t *) (args->data + flowset_base);
      len = flowset->record.length;
      swap_endianness(&len, sizeof(len));
      flowset_end = flowset_base + len;
      if (flowset_end >= total_packet_length) {
        fprintf(stderr, "%s %d %s: read all packet\n", __FILE__, __LINE__, __func__);
        break;
      }
      if (flowset_base == flowset_end) {
        fprintf(stderr, "%s %d %s: flowset_base == flowset_end\n", __FILE__, __LINE__, __func__);
        break;
      }
      // swap_endianness(&flowset_base,sizeof(flowset_base));
      // swap_endianness(&flowset_end,sizeof(flowset_end));
    }

    swap_endianness(&flowset->template.flowset_id, sizeof(flowset->template.flowset_id));
    swap_endianness(&flowset->template.length, sizeof(flowset->template.length));
    uint16_t flowset_id = flowset->template.flowset_id;
    uint16_t flowset_length = flowset->template.length;
    // uint16_t *template = NULL;
    fprintf(stderr, "%s %d %s: flowset_id: %d\n", __FILE__, __LINE__, __func__, flowset_id);
    fprintf(stderr, "%s %d %s: length: %d\n", __FILE__, __LINE__, __func__, flowset_length);

    if (0 == flowset_id) {
      // this is a template flowset
      fprintf(stderr, "%s %d %s: this is a template flowset\n", __FILE__, __LINE__, __func__);
      size_t has_more_templates = 1;
      size_t pos = 0;
      // end = flowset_base + length;
      template_counter = 0;
      while (has_more_templates) {
        size_t delta = pos - flowset_base;
        netflow_v9_flow_header_template_t *template =
            (netflow_v9_flow_header_template_t *) (args->data + pos + flowset_base);
        // ptr = &(template->templates[template_counter].template_id);
        // swap_endianness(&template->template_id,sizeof(template->template_id));
        uint16_t template_id = template->templates[0].template_id;
        uint16_t field_count = template->templates[0].field_count;

        swap_endianness(&template_id, sizeof(template_id));
        swap_endianness(&field_count, sizeof(field_count));
        if (template_id == 0) {
          goto unlock_mutex_parse_v9;
        }
        fprintf(stderr, "%s %d %s template_id: %d\n", __FILE__, __LINE__, __func__, template_id);
        fprintf(stderr, "%s %d %s field count: %d\n", __FILE__, __LINE__, __func__, field_count);
        // size_t start_fields = template->templates[0].fields;
        //  size_t end_fields = start_fields + field_count * 4;
        for (size_t field = 0; field < field_count; field++) {
          uint16_t t = (uint16_t) template->templates[0].fields[field].field_type;
          uint16_t l = (uint16_t) template->templates[0].fields[field].field_length;
          swap_endianness(&t, sizeof(t));
          swap_endianness(&l, sizeof(l));
          if (t == 0 || l == 0) {
            goto unlock_mutex_parse_v9;
          }
          if (t < sizeof(ipfix_field_types) / sizeof(ipfix_field_type_t)) {
#ifdef CNETFLOW_DEBUG_BUILD
            fprintf(stderr, "%s %d %s field: %d type: %u len: %u [%s]\n", __FILE__, __LINE__, __func__, field, t, l,
                    ipfix_field_types[t].name);
#endif
          } else {
            fprintf(stderr, "%s %d %s", __FILE__, __LINE__, __func__);
            assert(-1);
          }
        }
        pos += (field_count * 4) + 4;
        char key[255];
        snprintf(key, 255, "%s-%u", ip_int_to_str(args->exporter), template_id);
        fprintf(stderr, "%s %d %s: key: %s\n", __FILE__, __LINE__, __func__, key);
        uint16_t *template_hashmap = (uint16_t *) hashmap_get(templates_nfv9_hashmap, key, strlen(key));
        uint16_t *temp;
        size_t template_init = (size_t) &template->templates[0].fields[0].field_type;
        if (template_hashmap == NULL) {
          fprintf(stderr, "%s %d %s template %d not found for exporter %s\n", __FILE__, __LINE__, __func__, template_id,
                  ip_int_to_str(args->exporter));
          size_t template_end = template_init + sizeof(uint16_t) * field_count * 2;
          fprintf(stderr, "%s %d %s template_init: %lu template_end: %lu\n", __FILE__, __LINE__, __func__,
                  template_init, template_end);
          temp = arena_alloc(arena_hashmap_nf9, sizeof(uint16_t) * (field_count + 1) * 4);
          memcpy(temp, (void *) (template_init - sizeof(int16_t) * 2), sizeof(uint16_t) * (field_count + 1) * 4);
          if (hashmap_set(templates_nfv9_hashmap, arena_hashmap_nf9, key, strlen(key), temp)) {
            fprintf(stderr, "%s %d %s Error saving template in hashmap [%s]...\n", __FILE__, __LINE__, __func__, key);
          } else {
            fprintf(stderr, "%s %d %s Template saved in hashmap [%s]...\n", __FILE__, __LINE__, __func__, key);
          }
          // fprintf(stderr, "template %d not found for exporter %s\n", template_id, ip_int_to_str(args->exporter));
        } else {
          memcpy(template_hashmap, (void *) (template_init - sizeof(int16_t) * 2),
                 sizeof(uint16_t) * (field_count + 1) * 2);
        }
        fprintf(stderr, "%s %d %s: template_counter: %lu\n", __FILE__, __LINE__, __func__, template_counter);
        template_counter++;
        total_flowsets++;
        if (pos >= flowset_length - 4) {
          has_more_templates = 0;
        }
      }
    } else if (flowset_id >= 256) {
      // this a record flowset
      fprintf(stderr, "%s %d %s: this is a record flowset\n", __FILE__, __LINE__, __func__);

      size_t has_more_records = 1;
      size_t pos = 0;
      netflow_v9_record_t *record = (netflow_v9_record_t *) (args->data + flowset_base + pos);
      uint16_t template_id = flowset_id;
      char key[255];
      snprintf(key, 255, "%s-%u\0", ip_int_to_str(args->exporter), template_id);
      fprintf(stderr, "%s %d %s key: %s\n", __FILE__, __LINE__, __func__, key);
      uint16_t *template_hashmap = (uint16_t *) hashmap_get(templates_nfv9_hashmap, key, strlen(key));
      if (template_hashmap == NULL) {
        fprintf(stderr, "%s %d %s template %d not found for exporter %s\n", __FILE__, __LINE__, __func__, template_id,
                ip_int_to_str(args->exporter));
        pos = flowset_length;
        has_more_records = 0;
      } else {
        void *pointer = &record->record_value;
        uint16_t record_length = 0;
        uint16_t template_id = template_hashmap[0];
        swap_endianness(&template_id, sizeof(template_id));
        uint16_t field_count = template_hashmap[1];
        swap_endianness(&field_count, sizeof(field_count));
        pos = 0;
        // pos += 4;
        // FILE *ftemplate = fopen("templates.txt", "a");
        netflow_v9_flowset_t *netflow_packet_ptr;
        netflow_v9_flowset_t netflow_packet = {0};
        netflow_packet_ptr = &netflow_packet;
        int is_ipv6 = 0;
        while (has_more_records) {
          // netflow_v9_record_value_t *record_value;
          size_t print_flow = 0;
#ifdef CNETFLOW_DEBUG_BUILD
          fprintf(stdout, "exporter: %s template: %d flowsets: %d record_no: %d field_count: %d",
                  ip_int_to_str(args->exporter), template_id, flowsets + 1, record_counter + 1, field_count);
#endif
          size_t reading_field = 0;
          for (size_t count = 2; count < field_count * 2 + 2; count = count + 2) {
            reading_field++;
            uint16_t field_type = template_hashmap[count];
            swap_endianness(&field_type, sizeof(field_type));
            if (field_type > (sizeof(ipfix_field_types) / sizeof(ipfix_field_type_t))) {
              // assert(-1);
              // exit(-1);
              goto unlock_mutex_parse_v9;
            }
            uint16_t field_length = template_hashmap[count + 1];
            swap_endianness(&field_length, sizeof(field_length));
#ifdef CNETFLOW_DEBUG_BUILD
            fprintf(stdout, " field_no_%lu_%s[%d]_%d ", reading_field, ipfix_field_types[field_type].name, field_type,
                    field_length);
#endif
            /*if (field_type == 8) {
              printf("STAP!\n");
            }*/
            // record_length = ipfix_field_types[field].length;

            record_length = field_length;
            uint8_t *tmp8; // 1 byte
            uint16_t *tmp16; // 2 bytes
            uint32_t *tmp32; // 4 bytes
            uint64_t *tmp64; // 8 bytes
            uint64_t tmp6 = 0; // 6 bytes -> 8bytes
            uint128_t *tmp128; // 16bytes
            uint128_t val_tmp128; // 16bytes
            if (field_type > 337) {
              goto unlock_mutex_parse_v9;
            }

            switch (record_length) {
              case 1:
                tmp8 = (uint8_t *) pointer;
                // swap_endianness(tmp8, sizeof(*tmp8));
                break;
              case 2:
                tmp16 = (uint16_t *) pointer;
                // swap_endianness(tmp16, sizeof(*tmp16));
                break;
              case 4:
                tmp32 = (uint32_t *) pointer;
                // swap_endianness(tmp32, sizeof(*tmp32));
                break;
              case 6:
                tmp64 = (uint64_t *) pointer;
                tmp6 = *tmp64;
                tmp6 &= 0x0000ffffffffffff;
                // swap_endianness(&tmp6, sizeof(*tmp64));
                tmp6 = tmp6 >> 16;
                break;
              case 8:
                tmp64 = (uint64_t *) pointer;
                // swap_endianness(tmp64, sizeof(*tmp64));
                break;
              case 16:
                tmp128 = (uint128_t *) pointer;
                // assert(((uintptr_t) tmp128 % 16) == 0);
                memcpy(&val_tmp128, pointer, sizeof(uint128_t));
                // swap_endianness(tmp128, sizeof(*tmp128));
                break;
            }
            if (field_type == 21 || field_type == 22) {
            }
            if (field_type > 337) {
              goto unlock_mutex_parse_v9;
            }

            switch (field_type) {
              case IPFIX_FT_FLOWENDSYSUPTIME:
                swap_endianness(tmp32, sizeof(*tmp32));
                *tmp32 = *tmp32 / 1000 + diff;
                swap_endianness(tmp32, sizeof(*tmp32));
                netflow_packet_ptr->records[record_counter].Last = *tmp32;
                break;
              case IPFIX_FT_FLOWSTARTSYSUPTIME:
                swap_endianness(tmp32, sizeof(*tmp32));
                *tmp32 = *tmp32 / 1000 + diff;
                swap_endianness(tmp32, sizeof(*tmp32));
                netflow_packet_ptr->records[record_counter].First = *tmp32;
                break;
              case IPFIX_FT_IPVERSION:
                switch (*tmp8) {
                  case 4:
                    is_ipv6 = 0;
                    netflow_packet_ptr->records[record_counter].ip_version = 4;
                    break;
                  case 6:
                    is_ipv6 = 1;
                    netflow_packet_ptr->records[record_counter].ip_version = 6;
                    break;
                  default:
                    is_ipv6 = 0;
                    netflow_packet_ptr->records[record_counter].ip_version = 4;
                    break;
                }
                break;
              case IPFIX_FT_SOURCEIPV4ADDRESS:
                netflow_packet_ptr->records[record_counter].srcaddr = *tmp32;
                // swap_endianness(&netflow_packet_ptr->records[record_counter].srcaddr,
                //                sizeof(netflow_packet_ptr->records[record_counter].srcaddr));
                netflow_packet_ptr->records[record_counter].ip_version = 4;
                print_flow++;
                break;
              case IPFIX_FT_DESTINATIONIPV4ADDRESS:
                netflow_packet_ptr->records[record_counter].dstaddr = *tmp32;
                // swap_endianness(&netflow_packet_ptr->records[record_counter].dstaddr,
                //                sizeof(netflow_packet_ptr->records[record_counter].dstaddr));
                print_flow++;
                break;
              case IPFIX_FT_SOURCEIPV6ADDRESS:
                // assert(((uintptr_t) tmp128 % 16) == 0);
                netflow_packet_ptr->records[record_counter].ipv6srcaddr = val_tmp128;
                netflow_packet_ptr->records[record_counter].ip_version = 6;
                // swap_endianness(&netflow_packet_ptr->records[record_counter].srcaddr,
                //                sizeof(netflow_packet_ptr->records[record_counter].srcaddr));
                print_flow++;
                is_ipv6 = 1;
                break;
              case IPFIX_FT_DESTINATIONIPV6ADDRESS:
                netflow_packet_ptr->records[record_counter].ipv6dstaddr = val_tmp128;
                // swap_endianness(&netflow_packet_ptr->records[record_counter].dstaddr,
                //                sizeof(netflow_packet_ptr->records[record_counter].dstaddr));
                print_flow++;
                is_ipv6 = 1;
                break;
              case IPFIX_FT_OCTETDELTACOUNT:
                switch (record_length) {
                  case 4:
                    netflow_packet_ptr->records[record_counter].dOctets = (uint64_t) *tmp32;
                    netflow_packet_ptr->records[record_counter].dOctets <<= 32;
                    break;
                  case 8:
                    netflow_packet_ptr->records[record_counter].dOctets = (uint64_t) *tmp64;
                    // swap_endianness(&netflow_packet_ptr->records[record_counter].dOctets,
                    //                sizeof(netflow_packet_ptr->records[record_counter].dOctets));
                    break;
                  default:
                    netflow_packet_ptr->records[record_counter].dOctets = 0;
                    break;
                }
                print_flow++;
                break;
              case IPFIX_FT_PACKETDELTACOUNT: {
                uint64_t dpkts_64 = 0;
                uint32_t dpkts_32 = 0;
                switch (record_length) {
                  case 4:
                    netflow_packet_ptr->records[record_counter].dPkts = (uint64_t) *tmp32;
                    netflow_packet_ptr->records[record_counter].dPkts <<= 32;
                    break;
                  case 8:
                    netflow_packet_ptr->records[record_counter].dPkts = (uint64_t) *tmp64;
                    // swap_endianness(&netflow_packet_ptr->records[record_counter].dPkts,
                    //                sizeof(netflow_packet_ptr->records[record_counter].dPkts));
                    break;
                  default:
                    netflow_packet_ptr->records[record_counter].dPkts = 0;
                    break;
                }
                print_flow++;
                break;
              }
              case IPFIX_FT_DESTINATIONTRANSPORTPORT:
                netflow_packet_ptr->records[record_counter].dstport = *tmp16;
                print_flow++;
                break;
              case IPFIX_FT_SOURCETRANSPORTPORT:
                netflow_packet_ptr->records[record_counter].srcport = *tmp16;
                print_flow++;
                break;
              case IPFIX_FT_PROTOCOLIDENTIFIER:
                netflow_packet_ptr->records[record_counter].prot = *tmp8;
                print_flow++;
                break;
              case IPFIX_FT_INGRESSINTERFACE:
                switch (record_length) {
                  case 2:
                    netflow_packet_ptr->records[record_counter].input = *tmp16;
                    // netflow_packet_ptr->records[record_counter].input;
                    break;
                  case 4:
                    netflow_packet_ptr->records[record_counter].input = (uint16_t) ((*tmp32) >> 16);
                    // fprintf(stderr, "ingress tmp32: %d\n", *tmp32);
                    // fprintf(stderr, "ingress tmp32: %d\n", netflow_packet_ptr->records[record_counter].input);
                    break;
                  default:
                    netflow_packet_ptr->records[record_counter].input = 0;
                    break;
                }
                if (netflow_packet_ptr->records[record_counter].input > 3000) {
                  fprintf(stderr, "%s %d %s: input: %d\n", __FILE__, __LINE__, __func__,
                          netflow_packet_ptr->records[record_counter].input);
                }
                print_flow++;
                break;
              case IPFIX_FT_EGRESSINTERFACE:
                switch (record_length) {
                  case 2:
                    netflow_packet_ptr->records[record_counter].output = (uint32_t) *tmp16;
                    netflow_packet_ptr->records[record_counter].output <<= 16;
                    break;
                  case 4:
                    netflow_packet_ptr->records[record_counter].output = (uint16_t) ((*tmp32) >> 16);
                    fprintf(stderr, "egress tmp32: %d\n", *tmp32);
                    fprintf(stderr, "egress tmp32: %d\n", netflow_packet_ptr->records[record_counter].output);
                    break;
                  default:
                    netflow_packet_ptr->records[record_counter].output = 0;
                    break;
                }
                print_flow++;
                break;
              case IPFIX_FT_BGPSOURCEASNUMBER:
                switch (record_length) {
                  case 2:
                    netflow_packet_ptr->records[record_counter].src_as = (uint32_t) *tmp16;
                    // netflow_packet_ptr->records[record_counter].src_as <<= 16;
                    break;
                  case 4:
                    netflow_packet_ptr->records[record_counter].src_as = *tmp32;
                    break;
                  default:
                    netflow_packet_ptr->records[record_counter].src_as = 0;
                    break;
                }
                print_flow++;
                break;
              case IPFIX_FT_BGPDESTINATIONASNUMBER:
                switch (record_length) {
                  case 2:
                    netflow_packet_ptr->records[record_counter].dst_as = (uint32_t) *tmp16;
                    // netflow_packet_ptr->records[record_counter].dst_as <<= 16;
                    break;
                  case 4:
                    netflow_packet_ptr->records[record_counter].dst_as = *tmp32;
                    break;
                  default:
                    netflow_packet_ptr->records[record_counter].dst_as = 0;
                    break;
                }
                print_flow++;
                break;
              case IPFIX_FT_BGPNEXTHOPIPV4ADDRESS:
                netflow_packet_ptr->records[record_counter].nexthop = *tmp32;
                print_flow++;
                break;
              case IPFIX_FT_BGPNEXTHOPIPV6ADDRESS:
                netflow_packet_ptr->records[record_counter].ipv6nexthop = val_tmp128;
                is_ipv6 = 1;
                print_flow++;
                break;
              case IPFIX_FT_TCPCONTROLBITS:
                netflow_packet_ptr->records[record_counter].tcp_flags = *tmp8;
                print_flow++;
                break;
              case IPFIX_FT_IPCLASSOFSERVICE:
                netflow_packet_ptr->records[record_counter].tos = *tmp8;
                print_flow++;
                break;
              case IPFIX_FT_SOURCEIPV4PREFIXLENGTH:
                netflow_packet_ptr->records[record_counter].src_mask = *tmp8;
                print_flow++;
                break;
              case IPFIX_FT_DESTINATIONIPV4PREFIXLENGTH:
                netflow_packet_ptr->records[record_counter].dst_mask = *tmp8;
                print_flow++;
                break;
              case IPFIX_FT_SOURCEIPV6PREFIXLENGTH:
                netflow_packet_ptr->records[record_counter].src_mask = *tmp8;
                print_flow++;
                break;
              case IPFIX_FT_DESTINATIONIPV6PREFIXLENGTH:
                netflow_packet_ptr->records[record_counter].dst_mask = *tmp8;
                print_flow++;
                break;
              default:
                break;
            }

            if (field_type > 337) {
              goto unlock_mutex_parse_v9;
            }
#ifdef CNETFLOW_DEBUG_BUILD
            {
              switch (ipfix_field_types[field_type].coding) {
                case IPFIX_CODING_INT:
                  switch (record_length) {
                    case 1:
                      fprintf(stdout, "%d ", *tmp8);
                      break;
                    case 2:
                      fprintf(stdout, "%d ", *tmp16);
                      break;
                    case 4:
                      fprintf(stdout, "%d ", *tmp32);
                      break;
                    case 8:
                      fprintf(stdout, "%ld ", *tmp64);
                      break;
                  }
                  break;
                case IPFIX_CODING_UINT:
                  switch (record_length) {
                    case 1:
                      fprintf(stdout, "%u ", *tmp8);
                      break;
                    case 2:
                      fprintf(stdout, "%u ", *tmp16);
                      break;
                    case 4:
                      fprintf(stdout, "%u ", *tmp32);
                      break;
                    case 8:
                      fprintf(stdout, "%lu ", *tmp64);
                      break;
                  }
                  break;
                case IPFIX_CODING_BYTES:
                  switch (record_length) {
                    case 1:
                      fprintf(stdout, "%u ", *tmp8);
                      break;
                    case 2:
                      fprintf(stdout, "%u ", *tmp16);
                      break;
                    case 4:
                      fprintf(stdout, "%u ", *tmp32);
                      break;
                    case 6:
                      fprintf(stdout, "%lx ", tmp6);
                      break;
                    case 8:
                      fprintf(stdout, "%lu ", *tmp64);
                      break;
                  }
                  break;
                case IPFIX_CODING_STRING:
                  break;
                case IPFIX_CODING_FLOAT:
                  break;
                case IPFIX_CODING_NTP:
                  break;
                case IPFIX_CODING_IPADDR:
                  switch (record_length) {
                    case 4:
                      tmp8 = (uint8_t *) pointer;
                      fprintf(stdout, "%u.%u.%u.%u ", *(tmp8 + 3), *(tmp8 + 2), *(tmp8 + 1), *(tmp8));
                      break;
                    case 16:
                      tmp8 = (uint8_t *) pointer;
                      fprintf(stdout, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x ",
                              *(tmp8 + 15), *(tmp8 + 14), *(tmp8 + 13), *(tmp8 + 12), *(tmp8 + 11), *(tmp8 + 10),
                              *(tmp8 + 9), *(tmp8 + 8), *(tmp8 + 7), *(tmp8 + 6), *(tmp8 + 5), *(tmp8 + 4), *(tmp8 + 3),
                              *(tmp8 + 2), *(tmp8 + 1), *(tmp8 + 0));
                      break;
                    default:
                      exit(-1);
                      break;
                  }
                  break;
                default:
                  break;
              }
            }
#endif
            pointer += record_length;
            pos += record_length;
          }

#ifdef CNETFLOW_DEBUG_BUILD
          fprintf(stdout, "\n");
#endif
          if (!is_ipv6) {
            swap_endianness(&netflow_packet_ptr->records[record_counter].srcport,
                            sizeof(netflow_packet_ptr->records[record_counter].srcport));
            swap_endianness(&netflow_packet_ptr->records[record_counter].dstport,
                            sizeof(netflow_packet_ptr->records[record_counter].dstport));
            swap_src_dst_v9(&netflow_packet_ptr->records[record_counter]);
            swap_endianness(&netflow_packet_ptr->records[record_counter].srcport,
                            sizeof(netflow_packet_ptr->records[record_counter].srcport));
            swap_endianness(&netflow_packet_ptr->records[record_counter].dstport,
                            sizeof(netflow_packet_ptr->records[record_counter].dstport));
#ifdef CNETFLOW_DEBUG_BUILD
            printf_v9(stderr, netflow_packet_ptr, record_counter);
#endif
          } else {
            fprintf(stderr, "ipv6 not supported at the moment...\n");
          }
          record_counter++;
          if (pos >= flowset_length - 6) { // flowset_id + length + padding
            has_more_records = 0;
            // exit(-1);
          }
          if (record_counter + template_counter >= flowsets) {
            has_more_records = 0;
            // exit(-1);
          }
        }
        netflow_packet_ptr->header.count = record_counter;
        /*if (!is_ipv6) {

          // insert_v9(args->exporter, netflow_packet_ptr);
        } else {
          fprintf(stderr, "ipv6 got ipv6...\n");
        }
        */
        netflow_v9_uint128_flowset_t flows_to_insert = {0};
        copy_v9_to_flow(netflow_packet_ptr, &flows_to_insert, is_ipv6);
        uint32_t exporter_host = args->exporter;
        swap_endianness((void *) &exporter_host, sizeof(exporter_host));
        if (is_ipv6) {
          fprintf(stderr, "%s %d %s this is ipv6\n", __FILE__, __LINE__, __func__);
          insert_flows(exporter_host, &flows_to_insert);
        } else {
          fprintf(stderr, "%s %d %s this is ipv4\n", __FILE__, __LINE__, __func__);
          insert_flows(exporter_host, &flows_to_insert);
        }

        // fclose(ftemplate);
      }
    } else if ((flowset_id < 256)) {
      // this is an option flowset
      fprintf(stderr, "%s %d %s this is an option flowset\n", __FILE__, __LINE__, __func__);
    } else {
      fprintf(stderr, "%s %d %s this should not happen\n", __FILE__, __LINE__, __func__);
      goto unlock_mutex_parse_v9;
    }
  }


unlock_mutex_parse_v9:
  // uv_mutex_unlock(lock);
  args->status = collector_data_status_done;

  return NULL;
}


void copy_v9_to_flow(netflow_v9_flowset_t *in, netflow_v9_uint128_flowset_t *out, int is_ipv6) {
  fprintf(stderr, "%s %d %s copy_v9_to_flow entry\n", __FILE__, __LINE__, __func__);
  out->header.count = in->header.count;
  out->header.SysUptime = in->header.SysUptime;
  out->header.unix_secs = in->header.unix_secs;
  out->header.unix_nsecs = in->header.unix_nsecs;
  out->header.flow_sequence = in->header.flow_sequence;
  out->header.sampling_interval = in->header.sampling_interval;
  for (int i = 0; i < in->header.count; i++) {
    fprintf(stderr, "%s %d %s copy_v9_to_flow loop\n", __FILE__, __LINE__, __func__);
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
  fprintf(stderr, "%s %d %s copy_v9_to_flow return\n", __FILE__, __LINE__, __func__);
}
