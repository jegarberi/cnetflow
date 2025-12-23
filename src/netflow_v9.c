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

  //__attribute__((cleanup(uv_mutex_unlock))) uv_mutex_t * lock = &(args->mutex);
  netflow_v9_header_t *header = (netflow_v9_header_t *) (args->data);

  swap_endianness((void *) &(header->version), sizeof(header->version));
  if (header->version != 9) {
    goto unlock_mutex_parse_v9;
  }
  swap_endianness((void *) &(header->count), sizeof(header->count));
  if (header->count > 30000) {
    LOG_ERROR("%s %d %s: Too many flows\n", __FILE__, __LINE__, __func__);
    goto unlock_mutex_parse_v9;
  }
  size_t flowsets = header->count;
  LOG_ERROR("%s %d %s: flowsets in data: %d\n", __FILE__, __LINE__, __func__, header->count);
  swap_endianness((void *) &(header->SysUptime), sizeof(header->SysUptime));
  if (header->SysUptime == 1384148828) {
    LOG_ERROR("%s %d %s: SysUptime == 1384148828\n", __FILE__, __LINE__, __func__);
  }
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
  LOG_ERROR("%s %d %s: args->len: %lu\n", __FILE__, __LINE__, __func__, total_packet_length);

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
      if (flowset_end > total_packet_length) {
        LOG_ERROR("%s %d %s: read all packet\n", __FILE__, __LINE__, __func__);
        break;
      }
      if (flowset_base == flowset_end) {
        LOG_ERROR("%s %d %s: flowset_base == flowset_end\n", __FILE__, __LINE__, __func__);
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
    LOG_ERROR("%s %d %s: flowset_id: %d\n", __FILE__, __LINE__, __func__, flowset_id);
    LOG_ERROR("%s %d %s: length: %d\n", __FILE__, __LINE__, __func__, flowset_length);

    if (0 == flowset_id) {
      // this is a template flowset
      LOG_ERROR("%s %d %s: this is a template flowset\n", __FILE__, __LINE__, __func__);
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
        LOG_ERROR("%s %d %s template_id: %d\n", __FILE__, __LINE__, __func__, template_id);
        LOG_ERROR("%s %d %s field count: %d\n", __FILE__, __LINE__, __func__, field_count);
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
            LOG_ERROR("%s %d %s field: %d type: %u len: %u [%s]\n", __FILE__, __LINE__, __func__, field, t, l,
                    ipfix_field_types[t].name);
          } else {
            LOG_ERROR("%s %d %s", __FILE__, __LINE__, __func__);
            assert(-1);
          }
        }
        pos += (field_count * 4) + 4;
        char key[255];
        snprintf(key, 255, "%s-%u", ip_int_to_str(args->exporter), template_id);
        LOG_ERROR("%s %d %s: key: %s\n", __FILE__, __LINE__, __func__, key);
        uint16_t *template_hashmap = (uint16_t *) hashmap_get(templates_nfv9_hashmap, key, strlen(key));
        uint16_t *temp;
        size_t template_init = (size_t) &template->templates[0].fields[0].field_type;
        if (template_hashmap == NULL) {
          LOG_ERROR("%s %d %s template %d not found for exporter %s\n", __FILE__, __LINE__, __func__, template_id,
                  ip_int_to_str(args->exporter));
          size_t template_end = template_init + sizeof(uint16_t) * field_count * 2;
          LOG_ERROR("%s %d %s template_init: %lu template_end: %lu\n", __FILE__, __LINE__, __func__,
                  template_init, template_end);

          // CRITICAL FIX: Validate arena allocation before memcpy
          size_t alloc_size = sizeof(uint16_t) * (field_count + 1) * 4;
          temp = arena_alloc(arena_hashmap_nf9, alloc_size);
          if (temp == NULL) {
            LOG_ERROR("%s %d %s Failed to allocate %lu bytes for template\n",
                      __FILE__, __LINE__, __func__, alloc_size);
            goto unlock_mutex_parse_v9;
          }

          // Validate source address is within packet bounds
          size_t src_offset = template_init - sizeof(int16_t) * 2 - (size_t)args->data;
          size_t copy_size = sizeof(uint16_t) * (field_count + 1) * 4;
          if (src_offset + copy_size > total_packet_length) {
            LOG_ERROR("%s %d %s Template copy would exceed packet bounds\n", __FILE__, __LINE__, __func__);
            goto unlock_mutex_parse_v9;
          }

          memcpy(temp, (void *) (template_init - sizeof(int16_t) * 2), copy_size);
          if (hashmap_set(templates_nfv9_hashmap, arena_hashmap_nf9, key, strlen(key), temp)) {
            LOG_ERROR("%s %d %s Error saving template in hashmap [%s]...\n", __FILE__, __LINE__, __func__, key);
          } else {
            LOG_ERROR("%s %d %s Template saved in hashmap [%s]...\n", __FILE__, __LINE__, __func__, key);
          }
          // fprintf(stderr, "template %d not found for exporter %s\n", template_id, ip_int_to_str(args->exporter));
        } else {
          memcpy(template_hashmap, (void *) (template_init - sizeof(int16_t) * 2),
                 sizeof(uint16_t) * (field_count + 1) * 2);
        }
        LOG_ERROR("%s %d %s: template_counter: %lu\n", __FILE__, __LINE__, __func__, template_counter);
        template_counter++;
        total_flowsets++;
        if (pos >= flowset_length - 4) {
          has_more_templates = 0;
        }
      }
    } else if (flowset_id >= 256) {
      // this a record flowset
      LOG_ERROR("%s %d %s: this is a record flowset\n", __FILE__, __LINE__, __func__);

      // Validate flowset_base is within packet bounds
      if (flowset_base >= total_packet_length) {
        LOG_ERROR("%s %d %s: flowset_base %lu exceeds packet length %lu\n",
                  __FILE__, __LINE__, __func__, flowset_base, total_packet_length);
        goto unlock_mutex_parse_v9;
      }

      size_t has_more_records = 1;
      size_t pos = 0;

      // Validate we have enough space for record header
      if (flowset_base + pos + sizeof(netflow_v9_record_t) > total_packet_length) {
        LOG_ERROR("%s %d %s: Insufficient space for record at offset %lu\n",
                  __FILE__, __LINE__, __func__, flowset_base + pos);
        goto unlock_mutex_parse_v9;
      }

      netflow_v9_record_t *record = (netflow_v9_record_t *) (args->data + flowset_base + pos);
      uint16_t template_id = flowset_id;
      char key[255];
      snprintf(key, 255, "%s-%u\0", ip_int_to_str(args->exporter), template_id);
      LOG_ERROR("%s %d %s key: %s\n", __FILE__, __LINE__, __func__, key);
      uint16_t *template_hashmap = (uint16_t *) hashmap_get(templates_nfv9_hashmap, key, strlen(key));
      if (template_hashmap == NULL) {
        LOG_ERROR("%s %d %s template %d not found for exporter %s\n", __FILE__, __LINE__, __func__, template_id,
                ip_int_to_str(args->exporter));
        pos = flowset_length;
        has_more_records = 0;
      } else {
        // CRITICAL FIX: Validate record pointer before accessing record_value
        if (record == NULL) {
          LOG_ERROR("%s %d %s: record is NULL\n", __FILE__, __LINE__, __func__);
          goto unlock_mutex_parse_v9;
        }
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
          netflow_v9_record_insert_t empty_record = {0};
          for (size_t count = 2; count < field_count * 2 + 2; count = count + 2) {
            reading_field++;

            // CRITICAL FIX: Validate pointer is within packet bounds before accessing
            size_t pointer_offset = (size_t)pointer - (size_t)args->data;
            if (pointer_offset >= total_packet_length) {
              LOG_ERROR("%s %d %s: pointer offset %lu exceeds packet length %lu\n",
                        __FILE__, __LINE__, __func__, pointer_offset, total_packet_length);
              goto unlock_mutex_parse_v9;
            }

            uint16_t field_type = template_hashmap[count];
            swap_endianness(&field_type, sizeof(field_type));
            memcpy(&netflow_packet_ptr->records[record_counter], &empty_record, sizeof(netflow_v9_record_insert_t));
            if (field_type > (sizeof(ipfix_field_types) / sizeof(ipfix_field_type_t))) {
              // assert(-1);
              // exit(-1);
              goto unlock_mutex_parse_v9;
            }
            uint16_t field_length = template_hashmap[count + 1];
            swap_endianness(&field_length, sizeof(field_length));

            // Validate we have enough space for this field
            if (pointer_offset + field_length > total_packet_length) {
              LOG_ERROR("%s %d %s: field at offset %lu length %u exceeds packet bounds\n",
                        __FILE__, __LINE__, __func__, pointer_offset, field_length);
              goto unlock_mutex_parse_v9;
            }
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
            uint8_t val_tmp8 = 0;
            uint16_t *tmp16; // 2 bytes
            uint16_t val_tmp16 = 0;
            uint32_t *tmp32; // 4 bytes
            uint32_t val_tmp32 = 0;
            uint64_t *tmp64; // 8 bytes
            uint64_t val_tmp64 = 0;
            uint128_t *tmp128; // 16bytes
            uint128_t val_tmp128; // 16bytes
            if (field_type > 337) {
              goto unlock_mutex_parse_v9;
            }

            switch (record_length) {
              case 1:
                tmp8 = (uint8_t *) pointer;
                val_tmp8 = *tmp8;
                break;
              case 2:
                tmp16 = (uint16_t *) pointer;
                val_tmp16 = *tmp16;
                break;
              case 4:
                tmp32 = (uint32_t *) pointer;
                val_tmp32 = *tmp32;
                break;
              case 6:
                tmp64 = (uint64_t *) pointer;
                val_tmp64 = *tmp64;
                val_tmp64 &= 0x0000ffffffffffff;
                val_tmp64 = val_tmp64 >> 16;

                break;
              case 8:
                tmp64 = (uint64_t *) pointer;
                val_tmp64 = *tmp64;
                break;
              case 16:
                tmp128 = (uint128_t *) pointer;
                memcpy(&val_tmp128, pointer, sizeof(uint128_t));
                break;
            }
            if (field_type == 21 || field_type == 22) {
            }
            if (field_type > 337) {
              goto unlock_mutex_parse_v9;
            }

            switch (field_type) {
              case IPFIX_FT_FLOWENDSYSUPTIME:
                swap_endianness(&val_tmp32, sizeof(val_tmp32));
                val_tmp32 = val_tmp32 / 1000 + diff;
                swap_endianness(&val_tmp32, sizeof(val_tmp32));
                netflow_packet_ptr->records[record_counter].Last = val_tmp32;
                break;
              case IPFIX_FT_FLOWSTARTSYSUPTIME:
                swap_endianness(&val_tmp32, sizeof(val_tmp32));
                val_tmp32 = val_tmp32 / 1000 + diff;
                swap_endianness(&val_tmp32, sizeof(val_tmp32));
                netflow_packet_ptr->records[record_counter].First = val_tmp32;
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
                netflow_packet_ptr->records[record_counter].srcaddr = val_tmp32;
                // swap_endianness(&netflow_packet_ptr->records[record_counter].srcaddr,
                //                sizeof(netflow_packet_ptr->records[record_counter].srcaddr));
                netflow_packet_ptr->records[record_counter].ip_version = 4;
                print_flow++;
                break;
              case IPFIX_FT_DESTINATIONIPV4ADDRESS:
                netflow_packet_ptr->records[record_counter].dstaddr = val_tmp32;
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
                    netflow_packet_ptr->records[record_counter].dOctets = (uint64_t) val_tmp32;
                    netflow_packet_ptr->records[record_counter].dOctets <<= 32;
                    break;
                  case 8:
                    netflow_packet_ptr->records[record_counter].dOctets = (uint64_t) val_tmp64;
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
                // uint64_t dpkts_64 = 0;
                // uint32_t dpkts_32 = 0;
                switch (record_length) {
                  case 4:
                    netflow_packet_ptr->records[record_counter].dPkts = (uint64_t) val_tmp32;
                    netflow_packet_ptr->records[record_counter].dPkts <<= 32;
                    break;
                  case 8:
                    netflow_packet_ptr->records[record_counter].dPkts = (uint64_t) val_tmp64;
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
                switch (record_length) {
                case 2:
                    netflow_packet_ptr->records[record_counter].dstport = (uint16_t) val_tmp16;
                    break;
                case 4:
                    netflow_packet_ptr->records[record_counter].dstport = (uint16_t) ((val_tmp32) >> 16);
                    break;
                default:
                    netflow_packet_ptr->records[record_counter].dstport = 0;
                    break;
                }
                break;
              case IPFIX_FT_SOURCETRANSPORTPORT:
                switch (record_length) {
                case 2:
                    netflow_packet_ptr->records[record_counter].srcport = (uint16_t) val_tmp16;
                    break;
                case 4:
                    netflow_packet_ptr->records[record_counter].srcport = (uint16_t) ((val_tmp32) >> 16);
                    break;
                default:
                    netflow_packet_ptr->records[record_counter].srcport = 0;
                    break;
                }
                break;
              case IPFIX_FT_PROTOCOLIDENTIFIER:
                netflow_packet_ptr->records[record_counter].prot = val_tmp8;
                print_flow++;
                break;
              case IPFIX_FT_INGRESSINTERFACE:
                switch (record_length) {
                  case 2:
                    netflow_packet_ptr->records[record_counter].input = val_tmp16;
                    // netflow_packet_ptr->records[record_counter].input;
                    break;
                  case 4:
                    netflow_packet_ptr->records[record_counter].input = (uint16_t) ((val_tmp32) >> 16);
                    // fprintf(stderr, "ingress tmp32: %d\n", *tmp32);
                    // fprintf(stderr, "ingress tmp32: %d\n", netflow_packet_ptr->records[record_counter].input);
                    break;
                  default:
                    netflow_packet_ptr->records[record_counter].input = 0;
                    break;
                }
                if (netflow_packet_ptr->records[record_counter].input > 3000) {
                  LOG_ERROR("%s %d %s: input: %d\n", __FILE__, __LINE__, __func__,
                          netflow_packet_ptr->records[record_counter].input);
                }
                print_flow++;
                break;
              case IPFIX_FT_EGRESSINTERFACE:
                switch (record_length) {
                  case 2:
                    netflow_packet_ptr->records[record_counter].output = (uint32_t) val_tmp16;
                    netflow_packet_ptr->records[record_counter].output <<= 16;
                    break;
                  case 4:
                    netflow_packet_ptr->records[record_counter].output = (uint16_t) ((val_tmp32) >> 16);
                    LOG_ERROR("egress tmp32: %d\n", *tmp32);
                    LOG_ERROR("egress tmp32: %d\n", netflow_packet_ptr->records[record_counter].output);
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
                    netflow_packet_ptr->records[record_counter].src_as = (uint32_t) val_tmp16;
                    // netflow_packet_ptr->records[record_counter].src_as <<= 16;
                    break;
                  case 4:
                    netflow_packet_ptr->records[record_counter].src_as = val_tmp32;
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
                    netflow_packet_ptr->records[record_counter].dst_as = (uint32_t) val_tmp16;
                    // netflow_packet_ptr->records[record_counter].dst_as <<= 16;
                    break;
                  case 4:
                    netflow_packet_ptr->records[record_counter].dst_as = val_tmp32;
                    break;
                  default:
                    netflow_packet_ptr->records[record_counter].dst_as = 0;
                    break;
                }
                print_flow++;
                break;
              case IPFIX_FT_BGPNEXTHOPIPV4ADDRESS:
                netflow_packet_ptr->records[record_counter].nexthop = val_tmp32;
                print_flow++;
                break;
              case IPFIX_FT_BGPNEXTHOPIPV6ADDRESS:
                netflow_packet_ptr->records[record_counter].ipv6nexthop = val_tmp128;
                is_ipv6 = 1;
                print_flow++;
                break;
              case IPFIX_FT_TCPCONTROLBITS:
                netflow_packet_ptr->records[record_counter].tcp_flags = val_tmp8;
                print_flow++;
                break;
              case IPFIX_FT_IPCLASSOFSERVICE:
                netflow_packet_ptr->records[record_counter].tos = val_tmp8;
                print_flow++;
                break;
              case IPFIX_FT_SOURCEIPV4PREFIXLENGTH:
                netflow_packet_ptr->records[record_counter].src_mask = val_tmp8;
                print_flow++;
                break;
              case IPFIX_FT_DESTINATIONIPV4PREFIXLENGTH:
                netflow_packet_ptr->records[record_counter].dst_mask = val_tmp8;
                print_flow++;
                break;
              case IPFIX_FT_SOURCEIPV6PREFIXLENGTH:
                netflow_packet_ptr->records[record_counter].src_mask = val_tmp8;
                print_flow++;
                break;
              case IPFIX_FT_DESTINATIONIPV6PREFIXLENGTH:
                netflow_packet_ptr->records[record_counter].dst_mask = val_tmp8;
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
                      fprintf(stdout, "%d ", val_tmp8);
                      break;
                    case 2:
                      fprintf(stdout, "%d ", val_tmp16);
                      break;
                    case 4:
                      fprintf(stdout, "%d ", val_tmp32);
                      break;
                    case 8:
                      fprintf(stdout, "%ld ", val_tmp64);
                      break;
                  }
                  break;
                case IPFIX_CODING_UINT:
                  switch (record_length) {
                    case 1:
                      fprintf(stdout, "%u ", val_tmp8);
                      break;
                    case 2:
                      fprintf(stdout, "%u ", val_tmp16);
                      break;
                    case 4:
                      fprintf(stdout, "%u ", val_tmp32);
                      break;
                    case 8:
                      fprintf(stdout, "%lu ", val_tmp64);
                      break;
                  }
                  break;
                case IPFIX_CODING_BYTES:
                  switch (record_length) {
                    case 1:
                      fprintf(stdout, "%u ", val_tmp8);
                      break;
                    case 2:
                      fprintf(stdout, "%u ", val_tmp16);
                      break;
                    case 4:
                      fprintf(stdout, "%u ", val_tmp32);
                      break;
                    case 6:
                      fprintf(stdout, "%lx ", val_tmp64);
                      break;
                    case 8:
                      fprintf(stdout, "%lu ", val_tmp64);
                      break;
                  }
                  break;
                case IPFIX_CODING_STRING:
                case IPFIX_CODING_FLOAT:
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
                      EXIT_WITH_MSG(-1, "%s %d %s This should not happen...\n", __FILE__, __LINE__, __func__);
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
            swap_endianness(&netflow_packet_ptr->records[record_counter].srcaddr,
                            sizeof(netflow_packet_ptr->records[record_counter].srcaddr));
            swap_endianness(&netflow_packet_ptr->records[record_counter].dstaddr,
                            sizeof(netflow_packet_ptr->records[record_counter].dstaddr));


            swap_src_dst_v9_ipv4(&netflow_packet_ptr->records[record_counter]);
            swap_endianness(&netflow_packet_ptr->records[record_counter].srcport,
                            sizeof(netflow_packet_ptr->records[record_counter].srcport));
            swap_endianness(&netflow_packet_ptr->records[record_counter].dstport,
                            sizeof(netflow_packet_ptr->records[record_counter].dstport));
            swap_endianness(&netflow_packet_ptr->records[record_counter].srcaddr,
                            sizeof(netflow_packet_ptr->records[record_counter].srcaddr));
            swap_endianness(&netflow_packet_ptr->records[record_counter].dstaddr,
                            sizeof(netflow_packet_ptr->records[record_counter].dstaddr));
#ifdef CNETFLOW_DEBUG_BUILD
            printf_v9(stderr, netflow_packet_ptr, record_counter);
#endif
          } else {
            LOG_ERROR("ipv6 not supported at the moment...\n");
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
        memset(&flows_to_insert, 0, sizeof(flows_to_insert));
        if (netflow_packet_ptr->records[0].dOctets == 0) {
          LOG_ERROR("%s %d %s this is a zero flow\n", __FILE__, __LINE__, __func__);
        }
        if (netflow_packet_ptr->records[0].dPkts == 0) {
          LOG_ERROR("%s %d %s this is a zero flow\n", __FILE__, __LINE__, __func__);
        }
        copy_v9_to_flow(netflow_packet_ptr, &flows_to_insert, is_ipv6);
        uint32_t exporter_host = args->exporter;
        swap_endianness((void *) &exporter_host, sizeof(exporter_host));

        if (is_ipv6) {
          LOG_ERROR("%s %d %s this is ipv6\n", __FILE__, __LINE__, __func__);
          insert_flows(exporter_host, &flows_to_insert);
        } else {
          LOG_ERROR("%s %d %s this is ipv4\n", __FILE__, __LINE__, __func__);
          insert_flows(exporter_host, &flows_to_insert);
        }

        // fclose(ftemplate);
      }
    } else if ((flowset_id < 256)) {
      // this is an option flowset
      LOG_ERROR("%s %d %s this is an option flowset\n", __FILE__, __LINE__, __func__);
    } else {
      LOG_ERROR("%s %d %s this should not happen\n", __FILE__, __LINE__, __func__);
      goto unlock_mutex_parse_v9;
    }
    record_counter = 0;
  }


unlock_mutex_parse_v9:
  // uv_mutex_unlock(lock);
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
