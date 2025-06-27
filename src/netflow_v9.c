//
// Created by jon on 6/3/25.
//


#include "netflow_v9.h"
#include <assert.h>
static hashmap_t *templates_hashmap;
extern arena_struct_t *arena_collector;

void init_v9(arena_struct_t *arena, const size_t cap) {
  fprintf(stderr, "Initializing v9 [templates_hashmap]...\n");
  templates_hashmap = hashmap_create(arena, cap);
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
    fprintf(stderr, "Too many flows\n");
    goto unlock_mutex_parse_v9;
  }
  size_t flowsets = header->count;
  fprintf(stderr, "flowsets in data: %d\n", header->count);
  swap_endianness((void *) &(header->SysUptime), sizeof(header->SysUptime));
  swap_endianness((void *) &(header->unix_secs), sizeof(header->unix_secs));
  swap_endianness((void *) &(header->package_sequence), sizeof(header->package_sequence));
  swap_endianness((void *) &(header->source_id), sizeof(header->source_id));


  size_t end = 0;
  flowset_union_t *flowset;
  uint32_t now = (uint32_t) time(NULL);
  uint32_t diff = now - (uint32_t) (header->SysUptime / 1000);
  uint8_t process_flow = 1;
  size_t flowset_counter = 0;
  size_t record_counter = 0;
  size_t template_counter = 0;
  size_t flowset_base = 0;
  size_t flowset_end = 0;
  size_t total_flowsets = 0;
  uint16_t len = 0;
  size_t total_packet_length = args->len;
  fprintf(stderr, "args->len: %d\n", total_packet_length);

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
        fprintf(stderr, "read all packet\n");
        break;
      }
      if (flowset_base == flowset_end) {
        fprintf(stderr, "flowset_base == flowset_end\n");
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
    fprintf(stderr, "flowset_id: %d\n", flowset_id);
    fprintf(stderr, "length: %d\n", flowset_length);

    if (0 == flowset_id) {
      // this is a template flowset
      fprintf(stderr, "this is a template flowset\n");
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
        fprintf(stderr, "template_id: %d\n", template_id);
        fprintf(stderr, "field count: %d\n", field_count);
        // size_t start_fields = template->templates[0].fields;
        //  size_t end_fields = start_fields + field_count * 4;
        for (size_t field = 0; field < field_count; field++) {
          uint16_t t = (uint16_t) template->templates[0].fields[field].field_type;
          uint16_t l = (uint16_t) template->templates[0].fields[field].field_length;
          swap_endianness(&t, sizeof(t));
          swap_endianness(&l, sizeof(l));
          if (t == 0 || t == 0) {
            goto unlock_mutex_parse_v9;
          }
          if (t < sizeof(ipfix_field_types) / sizeof(ipfix_field_type_t)) {
            fprintf(stderr, "field: %d type: %u len: %u [%s]\n", field, t, l, ipfix_field_types[t].name);
          } else {
            assert(-1);
          }
        }
        pos += (field_count * 4) + 4;
        char key[255];
        snprintf(key, 255, "%s-%u", ip_int_to_str(args->exporter), template_id);
        fprintf(stderr, "key: %s\n", key);
        uint16_t *template_hashmap = (uint16_t *) hashmap_get(templates_hashmap, key, strlen(key));
        uint16_t *temp;
        size_t template_init = &template->templates[0].fields[0].field_type;
        if (template_hashmap == NULL) {
          fprintf(stderr, "%s %d %s template %d not found for exporter %s\n", __FILE__, __LINE__, __func__, template_id,
                  ip_int_to_str(args->exporter));
          size_t template_end = template_init + sizeof(uint16_t) * field_count * 2;
          fprintf(stderr, "%s %d %s template_init: %lu template_end: %lu\n", __FILE__, __LINE__, __func__,
                  template_init, template_end);
          temp = arena_alloc(arena_collector, sizeof(uint16_t) * (field_count + 1) * 4);
          memcpy(temp, (void *) (template_init - sizeof(int16_t) * 2), sizeof(uint16_t) * (field_count + 1) * 4);
          if (hashmap_set(templates_hashmap, arena_collector, key, strlen(key), temp)) {
            fprintf(stderr, "%s %d %s Error saving template in hashmap [%s]...\n", __FILE__, __LINE__, __func__, key);
          } else {
            fprintf(stderr, "%s %d %s Template saved in hashmap [%s]...\n", __FILE__, __LINE__, __func__, key);
          }
          // fprintf(stderr, "template %d not found for exporter %s\n", template_id, ip_int_to_str(args->exporter));
        } else {
          memcpy(template_hashmap, (void *) (template_init - sizeof(int16_t) * 2), sizeof(uint16_t) * field_count * 2);
        }
        fprintf(stderr, "template_counter: %lu\n", template_counter);
        template_counter++;
        total_flowsets++;
        if (pos >= flowset_length - 4) {
          has_more_templates = 0;
        }
      }
    } else if (flowset_id >= 256) {
      // this a record flowset
      fprintf(stderr, "this is a record flowset\n");
      size_t has_more_records = 1;
      size_t pos = 0;
      netflow_v9_record_t *record = (netflow_v9_record_t *) (args->data + flowset_base + pos);
      uint16_t template_id = flowset_id;
      char key[255];
      snprintf(key, 255, "%s-%u\0", ip_int_to_str(args->exporter), template_id);
      fprintf(stderr, "%s %d %s key: %s\n", __FILE__, __LINE__, __func__, key);
      uint16_t *template_hashmap = (uint16_t *) hashmap_get(templates_hashmap, key, strlen(key));
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
        FILE *ftemplate = fopen("templates.txt", "a");
        while (has_more_records) {
          // netflow_v9_record_value_t *record_value;

          fprintf(ftemplate, "exporter: %s template: %d flowsets: %d record_no: %d field_count: %d",
                  ip_int_to_str(args->exporter), template_id, flowsets + 1, record_counter + 1, field_count);
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
            fprintf(ftemplate, " field_no: %u %s[%d] %d ", reading_field, ipfix_field_types[field_type].name,
                    field_type, field_length);
            /*if (field_type == 8) {
              printf("STAP!\n");
            }*/
            // record_length = ipfix_field_types[field].length;
            record_length = field_length;
            uint8_t *tmp8;
            uint16_t *tmp16;
            uint32_t *tmp32;
            uint64_t *tmp64;
            uint128_t *tmp128;
            uint64_t tmp6 = 0;
            switch (record_length) {
              case 1:
                tmp8 = (uint8_t *) pointer;
                swap_endianness(tmp8, sizeof(uint8_t));
                break;
              case 2:
                tmp16 = (uint16_t *) pointer;
                swap_endianness(tmp16, sizeof(uint16_t));
                break;
              case 4:
                tmp32 = (uint32_t *) pointer;
                swap_endianness(tmp32, sizeof(uint32_t));
                break;
              case 6:
                tmp64 = (uint64_t *) pointer;
                tmp6 = *tmp64;
                tmp6 &= 0x0000ffffffffffff;
                swap_endianness(&tmp6, sizeof(uint64_t));
                tmp6 = tmp6 >> 16;
                break;
              case 8:
                tmp64 = (uint64_t *) pointer;
                swap_endianness(tmp64, sizeof(uint64_t));
                break;
              case 16:
                tmp128 = (uint128_t *) pointer;
                swap_endianness(tmp128, sizeof(uint128_t));
                break;
            }

            switch (ipfix_field_types[field_type].coding) {
              case IPFIX_CODING_INT:
                switch (record_length) {
                  case 1:
                    fprintf(ftemplate, "%d ", *tmp8);
                    break;
                  case 2:
                    fprintf(ftemplate, "%d ", *tmp16);
                    break;
                  case 4:
                    fprintf(ftemplate, "%d ", *tmp32);
                    break;
                  case 8:
                    fprintf(ftemplate, "%ld ", *tmp64);
                    break;
                }
                break;
              case IPFIX_CODING_UINT:
                switch (record_length) {
                  case 1:
                    fprintf(ftemplate, "%u ", *tmp8);
                    break;
                  case 2:
                    fprintf(ftemplate, "%u ", *tmp16);
                    break;
                  case 4:
                    fprintf(ftemplate, "%u ", *tmp32);
                    break;
                  case 8:
                    fprintf(ftemplate, "%lu ", *tmp64);
                    break;
                }
                break;
              case IPFIX_CODING_BYTES:
                switch (record_length) {
                  case 1:
                    fprintf(ftemplate, "%u ", *tmp8);
                    break;
                  case 2:
                    fprintf(ftemplate, "%u ", *tmp16);
                    break;
                  case 4:
                    fprintf(ftemplate, "%u ", *tmp32);
                    break;
                  case 6:
                    fprintf(ftemplate, "%lx ", tmp6);
                    break;
                  case 8:
                    fprintf(ftemplate, "%lu ", *tmp64);
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
                    fprintf(ftemplate, "%u.%u.%u.%u ", *(tmp8 + 3), *(tmp8 + 2), *(tmp8 + 1), *(tmp8));
                    break;
                  case 16:
                    tmp8 = (uint8_t *) pointer;
                    fprintf(ftemplate, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x ",
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
            pointer += record_length;
            pos += record_length;
          }
          fprintf(ftemplate, "\n");
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
        fclose(ftemplate);
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
