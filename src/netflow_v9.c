//
// Created by jon on 6/3/25.
//


#include "netflow_v9.h"
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
  size_t flowset_base = 0;
  size_t flowset_end = 0;
  size_t total_flowsets = 0;
  uint16_t len = 0;
  size_t total_packet_length = args->len;
  fprintf(stderr, "args->len: %d\n", total_packet_length);

  for (size_t flowset_counter = 0; flowset_counter < flowsets; ++flowset_counter) {
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
    uint16_t length = flowset->template.length;
    uint16_t *template = NULL;
    fprintf(stderr, "flowset_id: %d\n", flowset_id);
    fprintf(stderr, "length: %d\n", length);

    if (0 == flowset_id) {
      // this is a template flowset
      fprintf(stderr, "this is a template flowset\n");
      size_t has_more_templates = 1;
      size_t pos = 0;
      // end = flowset_base + length;
      size_t template_counter = 0;
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
        fprintf(stderr, "template_id: %d\n", template_id);
        fprintf(stderr, "field count: %d\n", field_count);
        // size_t start_fields = template->templates[0].fields;
        //  size_t end_fields = start_fields + field_count * 4;
        for (size_t field = 0; field < field_count; field++) {
          uint16_t t = (uint16_t) template->templates[0].fields[field].field_type;
          uint16_t l = (uint16_t) template->templates[0].fields[field].field_length;
          swap_endianness(&t, sizeof(t));
          swap_endianness(&l, sizeof(l));
          fprintf(stderr, "field: %d type: %u len: %u [%s]\n", field, t, l, ipfix_field_types[t].name);
        }
        pos += (field_count * 4) + 4;
        char key[255];
        snprintf(key, 255, "%s-%u", ip_int_to_str(args->exporter), template_id);
        fprintf(stderr, "key: %s\n", key);
        uint16_t *template_hashmap = (uint16_t *) hashmap_get(templates_hashmap, key, strlen(key));
        uint16_t *temp;
        size_t template_init = &template->templates[0].fields[0].field_type;
        if (template_hashmap == NULL) {
          fprintf(stderr, "template %d not found for exporter %s\n", template_id, ip_int_to_str(args->exporter));
          size_t template_end = template_init + sizeof(uint16_t) * field_count * 2;
          fprintf(stderr, "template_init: %lu template_end: %lu\n", template_init, template_end);
          temp = arena_alloc(arena_collector, sizeof(uint16_t) * field_count * 2 * 2);
          memcpy(temp, (void *) (template_init - sizeof(int16_t) * 2), sizeof(uint16_t) * field_count * 2);
          if (hashmap_set(templates_hashmap, arena_collector, key, strlen(key), temp)) {
            fprintf(stderr, "Error saving template in hashmap [%s]...\n", key);
          } else {
            fprintf(stderr, "Template saved in hashmap [%s]...\n", key);
          }
          // fprintf(stderr, "template %d not found for exporter %s\n", template_id, ip_int_to_str(args->exporter));
        } else {
          memcpy(template_hashmap, (void *) (template_init - sizeof(int16_t) * 2), sizeof(uint16_t) * field_count * 2);
        }
        fprintf(stderr, "template_counter: %lu\n", template_counter);
        template_counter++;
        total_flowsets++;
        if (pos >= length - 4) {
          has_more_templates = 0;
        }
      }
    } else if (flowset_id >= 256) {
      // this a record flowset
      fprintf(stderr, "this is a record flowset\n");
      netflow_v9_record_t *record = (netflow_v9_record_t *) (args->data + flowset_base);
      uint16_t template_id = flowset_id;
      char key[255];
      snprintf(key, 255, "%s-%u\0", ip_int_to_str(args->exporter), template_id);
      fprintf(stderr, "key: %s\n", key);

      template = (uint16_t *) hashmap_get(templates_hashmap, key, strlen(key));
      if (template == NULL) {
        fprintf(stderr, "template %d not found for exporter %s\n", template_id, ip_int_to_str(args->exporter));
      }
    } else if ((flowset_id < 256)) {
      // this is an option flowset
      fprintf(stderr, "this is an option flowset\n");
    } else {
      fprintf(stderr, "this should not happen\n");
      goto unlock_mutex_parse_v9;
    }
  }


unlock_mutex_parse_v9:
  // uv_mutex_unlock(lock);
  args->status = collector_data_status_done;

  return NULL;
}
