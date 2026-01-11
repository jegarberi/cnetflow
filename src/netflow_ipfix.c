//
// Created by jon on 6/3/25.
//


#include "netflow_ipfix.h"
#include <assert.h>
#include <stdio.h>
#include "log.h"
#include "netflow_v5.h"
#include "db.h"
static hashmap_t *templates_ipfix_hashmap;
extern arena_struct_t *arena_collector;
extern arena_struct_t *arena_hashmap_ipfix;

void init_ipfix(arena_struct_t *arena, const size_t cap) {
  LOG_ERROR("%s %d %s: Initializing IPFIX [templates_ipfix_hashmap]...\n", __FILE__, __LINE__, __func__);
  templates_ipfix_hashmap = hashmap_create(arena, cap);
}

void *parse_ipfix(uv_work_t *req) {

  parse_args_t *args = (parse_args_t *) req->data;
  args->status = collector_data_status_processing;

  if (args->len < sizeof(netflow_ipfix_header_t)) {
    LOG_ERROR("%s %d %s: Packet too short for IPFIX header: %lu\n", __FILE__, __LINE__, __func__, args->len);
    goto unlock_mutex_parse_ipfix;
  }

  netflow_ipfix_header_t *header = (netflow_ipfix_header_t *) (args->data);

  swap_endianness((void *) &(header->version), sizeof(header->version));
  if (header->version != 10) {
    LOG_ERROR("%s %d %s: Invalid IPFIX version: %d\n", __FILE__, __LINE__, __func__, header->version);
    goto unlock_mutex_parse_ipfix;
  }

  swap_endianness((void *) &(header->length), sizeof(header->length));
  swap_endianness((void *) &(header->ExportTime), sizeof(header->ExportTime));
  swap_endianness((void *) &(header->SequenceNumber), sizeof(header->SequenceNumber));
  swap_endianness((void *) &(header->ObsDomainId), sizeof(header->ObsDomainId));
  uint32_t now = (uint32_t) time(NULL);
  uint32_t diff = now - (uint32_t) (header->ExportTime);
  LOG_DEBUG("%s %d %s: IPFIX packet length: %d ExportTime: %u Sequence: %u Domain: %u Now: %u Diff: %u\n",
          __FILE__, __LINE__, __func__, header->length, header->ExportTime, header->SequenceNumber, header->ObsDomainId,
          now, diff);

  flowset_union_ipfix_t *flowset;

  size_t total_record_counter = 0;
  size_t record_counter = 0;
  size_t template_counter = 0;
  size_t flowset_base = 0;
  size_t flowset_end = 0;
  uint16_t len = 0;
  size_t total_packet_length = args->len;

  LOG_DEBUG("%s %d %s: args->len: %lu\n", __FILE__, __LINE__, __func__, total_packet_length);

  // Process all sets in the IPFIX message
  flowset_base = sizeof(netflow_ipfix_header_t);

  while (flowset_base + 4 <= total_packet_length && flowset_base + 4 <= header->length) {
    flowset = (flowset_union_ipfix_t *) (args->data + flowset_base);
    len = flowset->record.length;
    swap_endianness(&len, sizeof(len));

    if (len < 4 || flowset_base + len > total_packet_length) {
      LOG_ERROR("%s %d %s: Invalid set length: %d at offset %lu\n", __FILE__, __LINE__, __func__, len,
              flowset_base);
      break;
    }

    flowset_end = flowset_base + len;

    swap_endianness(&flowset->template.flowset_id, sizeof(flowset->template.flowset_id));
    swap_endianness(&flowset->template.length, sizeof(flowset->template.length));
    uint16_t flowset_id = flowset->template.flowset_id;
    uint16_t flowset_length = flowset->template.length;

    LOG_DEBUG("%s %d %s: flowset_id: %d length: %d\n", __FILE__, __LINE__, __func__, flowset_id, flowset_length);

    if (flowset_id == IPFIX_TEMPLATE_SET) {
      // Template Set (ID = 2)
      LOG_DEBUG("%s %d %s: Processing IPFIX template set\n", __FILE__, __LINE__, __func__);
      size_t pos = 4; // Skip set header (flowset_id + length)

      while (pos + 4 <= flowset_length && flowset_base + pos + 4 <= total_packet_length) {
        uint8_t *template_record_ptr = args->data + flowset_base + pos;
        uint16_t template_id = (template_record_ptr[0] << 8) | template_record_ptr[1];
        uint16_t field_count = (template_record_ptr[2] << 8) | template_record_ptr[3];


        if (template_id < 256) {
          LOG_ERROR("%s %d %s: Invalid template ID: %d\n", __FILE__, __LINE__, __func__, template_id);
          break;
        }


        // Template withdrawal (field_count = 0)
        if (field_count == 0) {
          LOG_ERROR("%s %d %s: Template withdrawal for ID: %d\n", __FILE__, __LINE__, __func__, template_id);
          pos += 4;
          continue;
        }

        LOG_ERROR("%s %d %s: template_id: %d field_count: %d\n", __FILE__, __LINE__, __func__, template_id,
                field_count);

        size_t template_size = 4; // template_id + field_count
        uint8_t *field_def_ptr = args->data + flowset_base + pos + 4;

        for (uint16_t i = 0; i < field_count; i++) {
          if (pos + template_size + 4 > flowset_length || flowset_base + pos + template_size + 4 > total_packet_length) {
            LOG_ERROR("%s %d %s: Template field definition OOB\n", __FILE__, __LINE__, __func__);
            goto unlock_mutex_parse_ipfix;
          }
          uint16_t ft = (field_def_ptr[0] << 8) | field_def_ptr[1];
          uint16_t fl = (field_def_ptr[2] << 8) | field_def_ptr[3];

          if (ft & 0x8000) {
            // Enterprise bit set
            if (pos + template_size + 8 > flowset_length || flowset_base + pos + template_size + 8 > total_packet_length) {
              LOG_ERROR("%s %d %s: Template field definition (enterprise) OOB\n", __FILE__, __LINE__, __func__);
              goto unlock_mutex_parse_ipfix;
            }
            uint32_t enterprise_id = (field_def_ptr[4] << 24) | (field_def_ptr[5] << 16) |
                                     (field_def_ptr[6] << 8) | field_def_ptr[7];
            LOG_ERROR("%s %d %s: field: %d type: %u (enterprise: %u) len: %u\n", __FILE__, __LINE__, __func__, i,
                      ft & 0x7FFF, enterprise_id, fl);
            template_size += 8;
            field_def_ptr += 8;
          } else {
            LOG_ERROR("%s %d %s: field: %d type: %u len: %u\n", __FILE__, __LINE__, __func__, i,
                      ft, fl);
            template_size += 4;
            field_def_ptr += 4;
          }
        }

        // Store template in hashmap
        char key[255];
        snprintf(key, 255, "%s-%u", ip_int_to_str(args->exporter), template_id);
        LOG_ERROR("%s %d %s: Storing template key: %s\n", __FILE__, __LINE__, __func__, key);

        uint16_t *template_hashmap = (uint16_t *) hashmap_get(templates_ipfix_hashmap, key, strlen(key));
        uint16_t *temp;
        uint8_t *template_record_start = args->data + flowset_base + pos;

        if (template_hashmap == NULL) {
          temp = arena_alloc(arena_hashmap_ipfix, template_size);
          memcpy(temp, (void *) template_record_start, template_size);

          if (hashmap_set(templates_ipfix_hashmap, arena_hashmap_ipfix, key, strlen(key), temp)) {
            LOG_ERROR("%s %d %s: Error saving IPFIX template [%s]\n", __FILE__, __LINE__, __func__, key);
          } else {
            LOG_ERROR("%s %d %s: IPFIX template saved [%s]\n", __FILE__, __LINE__, __func__, key);
          }
        } else {
          temp = arena_alloc(arena_hashmap_ipfix, template_size);
          memcpy(temp, (void *) template_record_start, template_size);
          hashmap_set(templates_ipfix_hashmap, arena_hashmap_ipfix, key, strlen(key), temp);
        }

        pos += template_size;
        template_counter++;
      }

    } else if (flowset_id >= 256) {


      // Data Set
      LOG_ERROR("%s %d %s: Processing IPFIX data set\n", __FILE__, __LINE__, __func__);

      uint16_t template_id = flowset_id;
      char key[255];
      snprintf(key, 255, "%s-%u", ip_int_to_str(args->exporter), template_id);
      LOG_ERROR("%s %d %s: Looking up template key: %s\n", __FILE__, __LINE__, __func__, key);

      uint16_t *template_hashmap = (uint16_t *) hashmap_get(templates_ipfix_hashmap, key, strlen(key));

      if (template_hashmap == NULL) {
        LOG_ERROR("%s %d %s: Template %d not found for exporter %s\n", __FILE__, __LINE__, __func__, template_id,
                ip_int_to_str(args->exporter));
      } else {
        if (args->exporter == 1090654892) {
          LOG_ERROR("%s %d %s: Exporter: %s [%u]\n", __FILE__, __LINE__, __func__, ip_int_to_str(args->exporter),
                  args->exporter);
        }
        void *pointer = args->data + flowset_base + 4; // Skip set header
        size_t pos = 4;

        uint16_t stored_template_id = template_hashmap[0];
        swap_endianness(&stored_template_id, sizeof(stored_template_id));
        uint16_t field_count = template_hashmap[1];
        swap_endianness(&field_count, sizeof(field_count));

        netflow_v9_flowset_t netflow_packet = {0};
        netflow_v9_flowset_t *netflow_packet_ptr = &netflow_packet;
        int is_ipv6 = 0;

        while (pos + 4 <= flowset_length) {
          if (record_counter >= 60) {
            LOG_ERROR("%s %d %s: Too many records in FlowSet (> 60), truncating\n", __FILE__, __LINE__, __func__);
            break;
          }
#ifdef CNETFLOW_DEBUG_BUILD
          fprintf(stdout, "exporter: %s template: %d record_no: %lu field_count: %u\n", ip_int_to_str(args->exporter),
                  template_id, record_counter + 1, field_count);
#endif

          size_t reading_field = 0;
          uint64_t sysUptimeMillis = 0;
          netflow_v9_record_insert_t empty_record = {0};
          memcpy(&netflow_packet.records[record_counter], &empty_record, sizeof(netflow_v9_record_insert_t));
          
          uint8_t *stored_field_ptr = (uint8_t *) template_hashmap + 4;

          for (uint16_t i = 0; i < field_count; i++) {
            reading_field++;
            uint16_t field_type = (stored_field_ptr[0] << 8) | stored_field_ptr[1];
            uint16_t field_length = (stored_field_ptr[2] << 8) | stored_field_ptr[3];
            
            size_t stored_field_def_size = (field_type & 0x8000) ? 8 : 4;

            // Mask off enterprise bit for now
            field_type = field_type & 0x7FFF;

            if (field_type >= (sizeof(ipfix_field_types) / sizeof(ipfix_field_type_t))) {
              LOG_ERROR("%s %d %s: Unknown IPFIX field type: %u\n", __FILE__, __LINE__, __func__, field_type);
              goto unlock_mutex_parse_ipfix;
            }

#ifdef CNETFLOW_DEBUG_BUILD
            fprintf(stdout, " field_%lu_%s[%d]_%d ", reading_field, 
                    ipfix_field_types[field_type].name ? ipfix_field_types[field_type].name : "unknown", 
                    field_type, field_length);
#endif

            uint16_t record_length = field_length;
            uint8_t *tmp8 = NULL;
            uint8_t val_tmp8 = 0;
            uint16_t *tmp16 = NULL;
            uint16_t val_tmp16 = 0;
            uint32_t *tmp32 = NULL;
            uint32_t val_tmp32 = 0;
            uint64_t *tmp64 = NULL;
            uint64_t val_tmp64 = 0;
            uint128_t *tmp128 = NULL;
            uint128_t val_tmp128 = 0;

            if ((uint8_t*)pointer + record_length > (uint8_t*)args->data + args->len ||
                pos + record_length > flowset_length) {
                LOG_ERROR("%s %d %s: Data record OOB! field: %d type: %u len: %u\n", __FILE__, __LINE__, __func__, i, field_type, record_length);
                goto unlock_mutex_parse_ipfix;
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
                memcpy(&val_tmp128, tmp128, sizeof(uint128_t));
                break;
            }

            // Process field based on IPFIX field type (same as NetFlow v9)
            switch (field_type) {
              case IPFIX_FT_SYSTEMINITTIMEMILLISECONDS:
                if (record_length == 8) {
                  swap_endianness(tmp64, sizeof(*tmp64));
                  sysUptimeMillis = *tmp64;
                }
                break;
              case IPFIX_FT_FLOWENDSYSUPTIME:
                if (record_length == 4) {
                  swap_endianness(&val_tmp32, sizeof(val_tmp32));
                  val_tmp32 = val_tmp32 / 1000 + diff;
                  swap_endianness(&val_tmp32, sizeof(val_tmp32));
                  netflow_packet_ptr->records[record_counter].Last = val_tmp32;
                } else if (record_length == 8) {
                  swap_endianness(&val_tmp64, sizeof(val_tmp64));
                  val_tmp64 = val_tmp64 / 1000 + diff;
                  uint32_t val32 = (uint32_t) val_tmp64;
                  swap_endianness(&val32, sizeof(val32));
                  netflow_packet_ptr->records[record_counter].Last = val32;
                }else {
                  netflow_packet_ptr->records[record_counter].Last = 0;
                }
                break;
              case IPFIX_FT_FLOWSTARTSYSUPTIME:
                if (record_length == 4) {
                  swap_endianness(&val_tmp32, sizeof(val_tmp32));
                  val_tmp32 = val_tmp32 / 1000 + diff;
                  swap_endianness(&val_tmp32, sizeof(val_tmp32));
                  netflow_packet_ptr->records[record_counter].First = val_tmp32;
                } else if (record_length == 8) {
                  swap_endianness(&val_tmp64, sizeof(val_tmp64));
                  val_tmp64 = val_tmp64 / 1000 + diff;
                  uint32_t val32 = (uint32_t) val_tmp64;
                  swap_endianness(&val32, sizeof(val32));
                  netflow_packet_ptr->records[record_counter].First = val32;
                }else {
                  netflow_packet_ptr->records[record_counter].First = 0;
                }
                break;
              case IPFIX_FT_FLOWSTARTMILLISECONDS:
                swap_endianness(&val_tmp64, sizeof(val_tmp64));
                val_tmp64 = val_tmp64 / 1000 + diff;
                {
                  uint32_t val32 = (uint32_t) val_tmp64;
                  swap_endianness(&val32, sizeof(val32));
                  netflow_packet_ptr->records[record_counter].First = val32;
                }
                break;
              case IPFIX_FT_FLOWENDMILLISECONDS:
                swap_endianness(&val_tmp64, sizeof(val_tmp64));
                val_tmp64 = val_tmp64 / 1000 + diff;
                {
                  uint32_t val32 = (uint32_t) val_tmp64;
                  swap_endianness(&val32, sizeof(val32));
                  netflow_packet_ptr->records[record_counter].Last = val32;
                }
                break;
              case IPFIX_FT_IPVERSION:
                switch (val_tmp8) {
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
                netflow_packet_ptr->records[record_counter].ip_version = 4;
                break;
              case IPFIX_FT_DESTINATIONIPV4ADDRESS:
                netflow_packet_ptr->records[record_counter].dstaddr = val_tmp32;
                break;
              case IPFIX_FT_SOURCEIPV6ADDRESS:
                netflow_packet_ptr->records[record_counter].ipv6srcaddr = val_tmp128;
                netflow_packet_ptr->records[record_counter].ip_version = 6;
                is_ipv6 = 1;
                break;
              case IPFIX_FT_DESTINATIONIPV6ADDRESS:
                netflow_packet_ptr->records[record_counter].ipv6dstaddr = val_tmp128;
                is_ipv6 = 1;
                break;
              case IPFIX_FT_OCTETDELTACOUNT:
                switch (record_length) {
                  case 4:
                    netflow_packet_ptr->records[record_counter].dOctets = ((uint64_t) val_tmp32) << 32;
                    break;
                  case 8:
                    netflow_packet_ptr->records[record_counter].dOctets = (uint64_t) val_tmp64;
                    break;
                  default:
                    netflow_packet_ptr->records[record_counter].dOctets = 0;
                    break;
                }
                break;
              case IPFIX_FT_PACKETDELTACOUNT:
                switch (record_length) {
                  case 4:
                    netflow_packet_ptr->records[record_counter].dPkts = ((uint64_t) val_tmp32) << 32;
                    break;
                  case 8:
                    netflow_packet_ptr->records[record_counter].dPkts = (uint64_t) val_tmp64;
                    break;
                  default:
                    netflow_packet_ptr->records[record_counter].dPkts = 0;
                    break;
                }
                break;
              case IPFIX_FT_DESTINATIONTRANSPORTPORT:
              case IPFIX_FT_TCPDESTINATIONPORT:
              case IPFIX_FT_UDPDESTINATIONPORT:
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
              case IPFIX_FT_TCPSOURCEPORT:
              case IPFIX_FT_UDPSOURCEPORT:
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
                break;
              case IPFIX_FT_INGRESSINTERFACE:
                switch (record_length) {
                  case 2:
                    netflow_packet_ptr->records[record_counter].input = val_tmp16;
                    break;
                  case 4:
                    netflow_packet_ptr->records[record_counter].input = (uint16_t) ((val_tmp32) >> 16);
                    break;
                  default:
                    netflow_packet_ptr->records[record_counter].input = 0;
                    break;
                }
                break;
              case IPFIX_FT_EGRESSINTERFACE:
                switch (record_length) {
                case 2:
                    netflow_packet_ptr->records[record_counter].output = val_tmp16;
                    break;
                case 4:
                    netflow_packet_ptr->records[record_counter].output = (uint16_t) ((val_tmp32) >> 16);
                    break;
                default:
                    netflow_packet_ptr->records[record_counter].output = 0;
                    break;
                }
                break;
              case IPFIX_FT_BGPSOURCEASNUMBER:
                switch (record_length) {
                  case 2:
                    netflow_packet_ptr->records[record_counter].src_as = ((uint32_t) val_tmp16 )<< 16;
                    break;
                  case 4:
                    netflow_packet_ptr->records[record_counter].src_as = val_tmp32;
                    break;
                  default:
                    netflow_packet_ptr->records[record_counter].src_as = 0;
                    break;
                }
                break;
              case IPFIX_FT_BGPDESTINATIONASNUMBER:
                switch (record_length) {
                  case 2:
                    netflow_packet_ptr->records[record_counter].dst_as = ((uint32_t) val_tmp16 )<< 16;
                    break;
                  case 4:
                    netflow_packet_ptr->records[record_counter].dst_as = val_tmp32;
                    break;
                  default:
                    netflow_packet_ptr->records[record_counter].dst_as = 0;
                    break;
                }
                break;
              case IPFIX_FT_BGPNEXTHOPIPV4ADDRESS:
                netflow_packet_ptr->records[record_counter].nexthop = val_tmp32;
                break;
              case IPFIX_FT_BGPNEXTHOPIPV6ADDRESS:
                netflow_packet_ptr->records[record_counter].ipv6nexthop = val_tmp128;
                is_ipv6 = 1;
                break;
              case IPFIX_FT_TCPCONTROLBITS:
                netflow_packet_ptr->records[record_counter].tcp_flags = val_tmp8;
                break;
              case IPFIX_FT_IPCLASSOFSERVICE:
                netflow_packet_ptr->records[record_counter].tos = val_tmp8;
                break;
              case IPFIX_FT_SOURCEIPV4PREFIXLENGTH:
                netflow_packet_ptr->records[record_counter].src_mask = val_tmp8;
                break;
              case IPFIX_FT_DESTINATIONIPV4PREFIXLENGTH:
                netflow_packet_ptr->records[record_counter].dst_mask = val_tmp8;
                break;
              case IPFIX_FT_SOURCEIPV6PREFIXLENGTH:
                netflow_packet_ptr->records[record_counter].src_mask = val_tmp8;
                break;
              case IPFIX_FT_DESTINATIONIPV6PREFIXLENGTH:
                netflow_packet_ptr->records[record_counter].dst_mask = val_tmp8;
                break;
              default:
                break;
            }

            pointer += record_length;
            pos += record_length;
            stored_field_ptr += stored_field_def_size;
          }

#ifdef CNETFLOW_DEBUG_BUILD
          fprintf(stdout, "\n");
#endif
          //if (netflow_packet_ptr->records[record_counter].prot == 1 && (netflow_packet_ptr->records[record_counter].srcport > 0 || netflow_packet_ptr->records[record_counter].dstport > 0)) {
          //  EXIT_WITH_MSG(-1, "%s %d %s this should not happen...\n", __FILE__, __LINE__, __func__);
          //}
          //if (sysUptimeMillis != 0 ) {

            LOG_ERROR("%s %d %s: sysUptimeMillis = %lu\n", __FILE__, __LINE__, __func__, sysUptimeMillis);
            LOG_ERROR("%s %d %s: Last = %u\n", __FILE__, __LINE__, __func__, netflow_packet_ptr->records[record_counter].Last);
            LOG_ERROR("%s %d %s: First = %u\n", __FILE__, __LINE__, __func__, netflow_packet_ptr->records[record_counter].First);
            swap_endianness(&netflow_packet_ptr->records[record_counter].Last,sizeof(netflow_packet_ptr->records[record_counter].Last));
            swap_endianness(&netflow_packet_ptr->records[record_counter].First,sizeof(netflow_packet_ptr->records[record_counter].First));
            uint32_t duration = netflow_packet_ptr->records[record_counter].Last -netflow_packet_ptr->records[record_counter].First;
            netflow_packet_ptr->records[record_counter].Last = now;
            netflow_packet_ptr->records[record_counter].First = now - duration;
            //netflow_packet_ptr->records[record_counter].Last = (sysUptimeMillis/1000) + netflow_packet_ptr->records[record_counter].Last;
            //netflow_packet_ptr->records[record_counter].Last = (sysUptimeMillis/1000) + netflow_packet_ptr->records[record_counter].Last;
            //netflow_packet_ptr->records[record_counter].First = (sysUptimeMillis/1000) + netflow_packet_ptr->records[record_counter].First;
            swap_endianness(&netflow_packet_ptr->records[record_counter].Last,sizeof(netflow_packet_ptr->records[record_counter].Last));
            swap_endianness(&netflow_packet_ptr->records[record_counter].First,sizeof(netflow_packet_ptr->records[record_counter].First));
          //}
          if (!is_ipv6) {

            swap_endianness(&netflow_packet_ptr->records[record_counter].srcport,
                            sizeof(netflow_packet_ptr->records[record_counter].srcport));
            swap_endianness(&netflow_packet_ptr->records[record_counter].dstport,
                            sizeof(netflow_packet_ptr->records[record_counter].dstport));
            swap_endianness(&netflow_packet_ptr->records[record_counter].srcaddr,
                            sizeof(netflow_packet_ptr->records[record_counter].srcaddr));
            swap_endianness(&netflow_packet_ptr->records[record_counter].dstaddr,
                            sizeof(netflow_packet_ptr->records[record_counter].dstaddr));

            swap_src_dst_ipfix_ipv4(&netflow_packet_ptr->records[record_counter]);

            swap_endianness(&netflow_packet_ptr->records[record_counter].srcport,
                            sizeof(netflow_packet_ptr->records[record_counter].srcport));
            swap_endianness(&netflow_packet_ptr->records[record_counter].dstport,
                            sizeof(netflow_packet_ptr->records[record_counter].dstport));
            swap_endianness(&netflow_packet_ptr->records[record_counter].srcaddr,
                            sizeof(netflow_packet_ptr->records[record_counter].srcaddr));
            swap_endianness(&netflow_packet_ptr->records[record_counter].dstaddr,
                            sizeof(netflow_packet_ptr->records[record_counter].dstaddr));

          }

          record_counter++;

          if (pos + 4 >= (size_t)flowset_length) {
            break;
          }
        }

        netflow_packet_ptr->header.count = record_counter;
        netflow_v9_uint128_flowset_t flows_to_insert = {0};
        memset(&flows_to_insert, 0, sizeof(flows_to_insert));
        copy_ipfix_to_flow(netflow_packet_ptr, &flows_to_insert, is_ipv6);

        uint32_t exporter_host = args->exporter;
        swap_endianness((void *) &exporter_host, sizeof(exporter_host));

        LOG_ERROR("%s %d %s: Inserting %lu IPFIX flows (%s)\n", __FILE__, __LINE__, __func__, record_counter,
                is_ipv6 ? "IPv6" : "IPv4");
        insert_flows(exporter_host, &flows_to_insert);
      }

    } else if (flowset_id == IPFIX_OPTION_SET) {
      // Options Template Set (ID = 3)
      LOG_ERROR("%s %d %s: IPFIX options template set (not implemented)\n", __FILE__, __LINE__, __func__);
    }

    flowset_base = flowset_end;
    total_record_counter++;
    record_counter = 0;
  }

  LOG_ERROR("%s %d %s: Processed %lu sets, %lu templates, %lu records\n", __FILE__, __LINE__, __func__,
          total_record_counter, template_counter, record_counter);

unlock_mutex_parse_ipfix:
  args->status = collector_data_status_done;
  return NULL;
}

void copy_ipfix_to_flow(netflow_v9_flowset_t *in, netflow_v9_uint128_flowset_t *out, int is_ipv6) {
  //fprintf(stderr, "%s %d %s: copy_ipfix_to_flow entry\n", __FILE__, __LINE__, __func__);
  out->header.count = in->header.count;
  out->header.SysUptime = in->header.SysUptime;
  out->header.unix_secs = in->header.unix_secs;
  out->header.unix_nsecs = in->header.unix_nsecs;
  out->header.flow_sequence = in->header.flow_sequence;
  out->header.sampling_interval = in->header.sampling_interval;

  for (int i = 0; i < in->header.count; i++) {
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

  //LOG_ERROR("%s %d %s: copy_ipfix_to_flow return\n", __FILE__, __LINE__, __func__);
}
