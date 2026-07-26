//
// Created by jon on 6/3/25.
//


#include "netflow_v9.h"
#include <assert.h>
#include <stdio.h>
#include "db.h"
#include "log.h"
#include "metrics.h"
#include "netflow_v5.h"
#include <arpa/inet.h>
#ifdef USE_REDIS
#include "redis_handler.h"
#endif

// ---------------------------------------------------------------------------
// Pending flowset queue — stores raw flowset data when template is not yet
// known, for later replay once the matching template arrives.
// ---------------------------------------------------------------------------
#define PENDING_QUEUE_MAX_PER_KEY 100000

typedef struct pending_flowset_s {
  uint8_t  *data;          // Raw copy of the flowset bytes (flowset_id + length + records)
  uint16_t  flowset_length;// Value of the flowset length field (already host-byte-order)
  uint32_t  exporter;      // Source exporter IP
  uint32_t  now;           // Snapshot of args->now at capture time
  uint32_t  SysUptime;     // Header SysUptime at capture time
  uint32_t  unix_secs;     // Header unix_secs at capture time
  uint32_t  package_sequence;
  uint32_t  source_id;
  uint32_t  flags;
  uint32_t  frame_number;
  struct pending_flowset_s *next;
} pending_flowset_t;

typedef struct {
  pending_flowset_t *head;
  pending_flowset_t *tail;
  size_t count;
} pending_queue_t;

static hashmap_t *templates_nfv9_hashmap;
static hashmap_t *pending_nfv9_hashmap;  // (exporter<<32|template_id) -> pending_queue_t*

uv_mutex_t v9_parse_mutex;

extern arena_struct_t *arena_collector;
extern arena_struct_t *arena_hashmap_nf9;

void init_v9(arena_struct_t *arena, const size_t cap) {
  LOG_ERROR("%s %d %s: Initializing v9 (Hashmap)...\n", __FILE__, __LINE__, __func__);
  templates_nfv9_hashmap = hashmap_create(arena, cap);
  pending_nfv9_hashmap   = hashmap_create(arena, cap);
  uv_mutex_init(&v9_parse_mutex);

#ifdef USE_REDIS
  LOG_ERROR("%s %d %s: Loading templates from Redis...\n", __FILE__, __LINE__, __func__);
  char **keys = NULL;
  size_t count = 0;
  if (redis_get_keys("*-9-*", &keys, &count) == 0) {
    for (size_t i = 0; i < count; i++) {
      size_t val_len = 0;
      void *val = redis_get_template(keys[i], strlen(keys[i]), &val_len);
      if (val) {
        void *arena_val = arena_alloc(arena, val_len);
        if (arena_val) {
          memcpy(arena_val, val, val_len);
          char ip_str[32] = {0};
          uint16_t tid = 0;
          if (sscanf(keys[i], "%31[^-]-9-%hu", ip_str, &tid) == 2) {
             struct in_addr in;
             if (inet_pton(AF_INET, ip_str, &in) == 1) {
                 uint64_t hkey = ((uint64_t)in.s_addr << 32) | tid;
                 hashmap_set(templates_nfv9_hashmap, arena, &hkey, sizeof(uint64_t), arena_val);
                 LOG_INFO("Loaded template %s from Redis\n", keys[i]);
             }
          }
        }
        free(val);
      }
    }
    redis_free_keys(keys, count);
  }
#endif
}

// ---------------------------------------------------------------------------
// Enqueue a raw flowset for later replay once its template arrives.
// Copies flowset_length bytes from flowset_data into the arena.
// Returns 1 on success, 0 if queue is full or allocation fails.
// ---------------------------------------------------------------------------
static int enqueue_pending_flowset(uint64_t hkey,
                                    const uint8_t *flowset_data,
                                    uint16_t flowset_length,
                                    uint32_t exporter,
                                    uint32_t now,
                                    uint32_t SysUptime,
                                    uint32_t unix_secs,
                                    uint32_t package_sequence,
                                    uint32_t source_id,
                                    uint32_t flags,
                                    uint32_t frame_number) {
  if (unlikely(pending_nfv9_hashmap == NULL)) return 0;
  pending_queue_t *q = (pending_queue_t *) hashmap_get(pending_nfv9_hashmap, &hkey, sizeof(uint64_t));

  if (q == NULL) {
    q = (pending_queue_t *) arena_alloc(arena_hashmap_nf9, sizeof(pending_queue_t));
    if (q == NULL) return 0;
    q->head = NULL; q->tail = NULL; q->count = 0;
    hashmap_set(pending_nfv9_hashmap, arena_hashmap_nf9, &hkey, sizeof(uint64_t), q);
  }
  if (q->count >= PENDING_QUEUE_MAX_PER_KEY) {
    LOG_ERROR("pending_queue: dropping oldest flowset for key %lx (queue full)\n", (unsigned long)hkey);
    // Drop oldest entry to make room
    pending_flowset_t *old = q->head;
    q->head = old->next;
    if (q->head == NULL) q->tail = NULL;
    q->count--;
    // Note: arena memory is not freed; it's bump-allocated and will be reclaimed at arena_clean time
  }
  pending_flowset_t *pf = (pending_flowset_t *) arena_alloc(arena_hashmap_nf9, sizeof(pending_flowset_t));
  if (pf == NULL) return 0;
  uint8_t *buf = (uint8_t *) arena_alloc(arena_hashmap_nf9, flowset_length);
  if (buf == NULL) return 0;
  memcpy(buf, flowset_data, flowset_length);
  pf->data             = buf;
  pf->flowset_length   = flowset_length;
  pf->exporter         = exporter;
  pf->now              = now;
  pf->SysUptime        = SysUptime;
  pf->unix_secs        = unix_secs;
  pf->package_sequence = package_sequence;
  pf->source_id        = source_id;
  pf->flags            = flags;
  pf->frame_number     = frame_number;
  pf->next             = NULL;
  if (q->tail) q->tail->next = pf; else q->head = pf;
  q->tail = pf;
  q->count++;
  LOG_ERROR("pending_queue: enqueued flowset (key %lx, len %u, queue depth %zu)\n",
            (unsigned long)hkey, flowset_length, q->count);
  return 1;
}

// Forward-declare decode helper (defined below parse_v9 in the original flow).
static void decode_v9_data_flowset(const uint8_t *flowset_data,
                                    uint16_t flowset_length,
                                    uint16_t *template_hashmap,
                                    uint32_t exporter,
                                    uint32_t now,
                                    uint32_t SysUptime,
                                    uint32_t unix_secs,
                                    uint32_t package_sequence,
                                    uint32_t source_id,
                                    uint32_t flags,
                                    uint32_t frame_number);

// ---------------------------------------------------------------------------
// Flush all pending flowsets for a given (exporter, template_id) key now that
// the template has been stored in templates_nfv9_hashmap.
// ---------------------------------------------------------------------------
static void flush_pending_flowsets(uint64_t hkey) {
  pending_queue_t *q = (pending_queue_t *) hashmap_get(pending_nfv9_hashmap, &hkey, sizeof(uint64_t));
  if (q == NULL || q->count == 0) return;

  uint16_t *tmpl = (uint16_t *) hashmap_get(templates_nfv9_hashmap, &hkey, sizeof(uint64_t));
  if (tmpl == NULL) return; // shouldn't happen

  LOG_ERROR("pending_queue: replaying %zu flowset(s) for key %lx\n", q->count, (unsigned long)hkey);

  for (pending_flowset_t *pf = q->head; pf != NULL; pf = pf->next) {
    // Validate record size still matches before replaying
    uint16_t field_count = tmpl[1];
    {
      uint16_t fc = field_count;
      swap_endianness(&fc, sizeof(fc));
      field_count = fc;
    }
    size_t record_size = 0;
    for (size_t c = 2; c < field_count * 2 + 2; c += 2) {
      uint16_t fl = tmpl[c + 1];
      swap_endianness(&fl, sizeof(fl));
      record_size += fl;
    }
    size_t data_len = (pf->flowset_length > 4) ? (pf->flowset_length - 4) : 0;
    if (record_size == 0) continue;
    size_t remainder = data_len % record_size;
    if (remainder != 0 && !(pf->flowset_length % 4 == 0 && remainder < 4)) {
      LOG_ERROR("pending_queue: skipping replayed flowset (size mismatch: data=%zu record=%zu remainder=%zu)\n",
                data_len, record_size, remainder);
      continue;
    }
    decode_v9_data_flowset(pf->data, pf->flowset_length, tmpl,
                           pf->exporter, pf->now, pf->SysUptime, pf->unix_secs,
                           pf->package_sequence, pf->source_id, pf->flags, pf->frame_number);
  }
  // Clear the queue (entries are arena-allocated; they'll be reclaimed at arena_clean)
  q->head = NULL; q->tail = NULL; q->count = 0;
}

void *parse_v9(uv_work_t *req) {
  uint16_t *template_hashmap = NULL;
  parse_args_t *args = (parse_args_t *) req->data;
  uv_mutex_lock(&v9_parse_mutex);
  uint64_t total_flows_in_packet = 0;
  if (unlikely(templates_nfv9_hashmap == NULL)) {
    goto cleanup_template_and_unlock;
  }
  args->status = collector_data_status_processing;

  netflow_v9_header_t *header = (netflow_v9_header_t *) (args->data);

  swap_endianness((void *) &(header->version), sizeof(header->version));
  if (unlikely(header->version != 9)) {
    goto cleanup_template_and_unlock;
  }
  swap_endianness((void *) &(header->count), sizeof(header->count));
  if (unlikely(header->count > 30000)) {
    LOG_ERROR("%s %d %s: Too many flows\n", __FILE__, __LINE__, __func__);
    goto cleanup_template_and_unlock;
  }
  LOG_ERROR("%s %d %s: flowsets in data: %d\n", __FILE__, __LINE__, __func__, header->count);
  swap_endianness((void *) &(header->SysUptime), sizeof(header->SysUptime));
  if (header->SysUptime == 1384148828) {
    LOG_ERROR("%s %d %s: SysUptime == 1384148828\n", __FILE__, __LINE__, __func__);
  }
  swap_endianness((void *) &(header->unix_secs), sizeof(header->unix_secs));
  swap_endianness((void *) &(header->package_sequence), sizeof(header->package_sequence));
  swap_endianness((void *) &(header->source_id), sizeof(header->source_id));

  uint32_t now = args->now;
  uint32_t diff = now - (uint32_t) (header->SysUptime / 1000);

  flowset_union_t *flowset;

  size_t record_counter = 0;
  size_t flowset_base = 0;
  size_t flowset_end = 0;
  uint16_t len = 0;
  size_t total_packet_length = args->len;
  LOG_ERROR("%s %d %s: args->len: %lu\n", __FILE__, __LINE__, __func__, total_packet_length);
  int8_t has_padding = 0;
  flowset_base = sizeof(netflow_v9_header_t);
  while (flowset_base + 4 <= total_packet_length) {
      flowset = (flowset_union_t *) (args->data + flowset_base);
      len = flowset->record.length;
      swap_endianness(&len, sizeof(len));
      
      if (unlikely(len < 4 || flowset_base + len > total_packet_length)) {
          LOG_ERROR("%s %d %s: Invalid flowset length: %d at offset %lu\n", __FILE__, __LINE__, __func__, len, flowset_base);
          break;
      }
      
      flowset_end = flowset_base + len;
      if (flowset_end % 32 != 0) {
        has_padding = 1;
      } else {
        has_padding = 0;
      }

    swap_endianness(&flowset->template.flowset_id, sizeof(flowset->template.flowset_id));
    swap_endianness(&flowset->template.length, sizeof(flowset->template.length));
    uint16_t flowset_id = flowset->template.flowset_id;
    uint16_t flowset_length = flowset->template.length;

    if (0 == flowset_id) {
      LOG_ERROR("%s %d %s: flowset_id: %d\n", __FILE__, __LINE__, __func__, flowset_id);
      LOG_ERROR("%s %d %s: length: %d\n", __FILE__, __LINE__, __func__, flowset_length);
      // this is a template flowset
      LOG_ERROR("%s %d %s: this is a template flowset\n", __FILE__, __LINE__, __func__);
      size_t pos = 4; // Skip flowset_id and length
      while (pos + 4 <= flowset_length) {
        uint8_t *template_ptr = args->data + flowset_base + pos;
        uint16_t template_id = (template_ptr[0] << 8) | template_ptr[1];
        uint16_t field_count = (template_ptr[2] << 8) | template_ptr[3];

        if (unlikely(template_id == 0)) {
          goto cleanup_template_and_unlock;
        }
        
        LOG_ERROR("%s %d %s template_id: %d\n", __FILE__, __LINE__, __func__, template_id);
        LOG_ERROR("%s %d %s field count: %d\n", __FILE__, __LINE__, __func__, field_count);

        if (unlikely(pos + 4 + field_count * 4 > flowset_length)) {
          LOG_ERROR("%s %d %s: Template field definition OOB\n", __FILE__, __LINE__, __func__);
          goto cleanup_template_and_unlock;
        }

        uint8_t *fields_ptr = template_ptr + 4;
        for (size_t field = 0; field < field_count; field++) {
          uint16_t t = (fields_ptr[field * 4] << 8) | fields_ptr[field * 4 + 1];
          uint16_t l = (fields_ptr[field * 4 + 2] << 8) | fields_ptr[field * 4 + 3];
          
          if (t == 0 || l == 0) {
            goto cleanup_template_and_unlock;
          }
          if (t < sizeof(ipfix_field_types) / sizeof(ipfix_field_type_t)) {
            LOG_ERROR("%s %d %s field: %d type: %u len: %u [%s]\n", __FILE__, __LINE__, __func__, field, t, l,
                      ipfix_field_types[t].name);
          } else {
            LOG_ERROR("%s %d %s field: %d type: %u len: %u [unknown]\n", __FILE__, __LINE__, __func__, field, t, l);
          }
        }
        
        char redis_key[255];
        snprintf(redis_key, 255, "%s-9-%u", ip_int_to_str(args->exporter), template_id);
        uint64_t hkey = ((uint64_t)args->exporter << 32) | template_id;
        LOG_ERROR("%s %d %s: key: %s\n", __FILE__, __LINE__, __func__, redis_key);

        // Prepare template data (Network Byte Order for hashmap)
        size_t alloc_size = sizeof(uint16_t) * (field_count + 1) * 2;

        // We use arena_hashmap_nf9 as temporary storage for construction
        uint16_t *temp = arena_alloc(arena_hashmap_nf9, alloc_size);
        if (temp == NULL) {
          LOG_ERROR("%s %d %s Failed to allocate %lu bytes for template\n", __FILE__, __LINE__, __func__, alloc_size);
          goto cleanup_template_and_unlock;
        }

        // Copy template data to buffer: exactly template_id, field_count, and then fields
        memcpy(temp, template_ptr, alloc_size);

        // Store in Hashmap
        hashmap_set(templates_nfv9_hashmap, arena_hashmap_nf9, &hkey, sizeof(uint64_t), temp);
        LOG_ERROR("%s %d %s Template saved in Hashmap [%s]...\n", __FILE__, __LINE__, __func__, redis_key);

        // Replay any flowsets that arrived before this template was known
        flush_pending_flowsets(hkey);


#ifdef USE_REDIS
        if (redis_set_template(redis_key, strlen(redis_key), temp, alloc_size) != 0) {
          LOG_ERROR("%s %d %s Error saving template in Redis [%s]...\n", __FILE__, __LINE__, __func__, redis_key);
        } else {
          LOG_ERROR("%s %d %s Template saved in Redis [%s]...\n", __FILE__, __LINE__, __func__, redis_key);
        }
#endif

#ifdef ENABLE_METRICS
        metrics_inc_v9_templates_received();
#endif

        // Track the exporter and flowsets
        metrics_track_exporter(args->exporter);
        metrics_inc_flowsets(1);

        pos += 4 + field_count * 4;
      }
    } else if (flowset_id >= 256) {
      if (args->flags == 1) {
        goto skip_v9_record_pass;
      }
      // this a record flowset
      LOG_ERROR("%s %d %s: flowset_id: %d\n", __FILE__, __LINE__, __func__, flowset_id);
      LOG_ERROR("%s %d %s: length: %d\n", __FILE__, __LINE__, __func__, flowset_length);
      LOG_ERROR("%s %d %s: this is a record flowset\n", __FILE__, __LINE__, __func__);

      // Validate flowset_base is within packet bounds
      if (unlikely(flowset_base >= total_packet_length)) {
        LOG_ERROR("%s %d %s: flowset_base %lu exceeds packet length %lu\n", __FILE__, __LINE__, __func__, flowset_base,
                  total_packet_length);
        goto cleanup_template_and_unlock;
      }

      size_t pos = 0;

      // Validate we have enough space for record header
      if (unlikely(flowset_base + pos > total_packet_length)) {
        LOG_ERROR("%s %d %s: Insufficient space for record at offset %lu\n", __FILE__, __LINE__, __func__,
                  flowset_base + pos);
        goto cleanup_template_and_unlock;
      }

      uint16_t template_id = flowset_id;
      uint64_t hkey = ((uint64_t)args->exporter << 32) | template_id;
      template_hashmap = (uint16_t *) hashmap_get(templates_nfv9_hashmap, &hkey, sizeof(uint64_t));

      if (template_hashmap == NULL) {
        LOG_ERROR("%s %d %s template %d not found for exporter %s — queuing for later\n", __FILE__, __LINE__, __func__, template_id,
                  ip_int_to_str(args->exporter));
        enqueue_pending_flowset(hkey,
                                (const uint8_t *)(args->data + flowset_base),
                                flowset_length,
                                args->exporter,
                                args->now,
                                header->SysUptime,
                                header->unix_secs,
                                header->package_sequence,
                                header->source_id,
                                args->flags,
                                args->frame_number);
      } else {
        void *pointer = args->data + flowset_base + 4;
        uint16_t field_count = template_hashmap[1];
        swap_endianness(&field_count, sizeof(field_count));
        // SKIP FLOWSET HEADER
        pos = 4;
        netflow_v9_uint128_flowset_t flows_to_insert;
        memset(&flows_to_insert, 0, sizeof(flows_to_insert));
        int is_ipv6 = 0;
        uint64_t local_v9_records = 0;

        // Track the exporter and flowsets per completely parsed template loop
        metrics_track_exporter(args->exporter);
        metrics_inc_flowsets(1);

        // Compute total size of one record based on template fields
        size_t total_record_size = 0;
        for (size_t count = 2; count < field_count * 2 + 2; count += 2) {
            uint16_t flen = template_hashmap[count + 1];
            swap_endianness(&flen, sizeof(flen));
            total_record_size += flen;
        }

        if (unlikely(total_record_size == 0)) {
            LOG_ERROR("%s %d %s: Template %d has 0 record size\n", __FILE__, __LINE__, __func__, template_id);
            goto cleanup_template_and_unlock;
        }

        // Validate: flowset data length must be a multiple of record size, plus up to 3 bytes padding (if 32-bit aligned).
        // If not, queue the raw bytes for replay once the updated template arrives.
        size_t flowset_data_len = (flowset_length > 4) ? (flowset_length - 4) : 0;
        size_t remainder = flowset_data_len % total_record_size;
        if (unlikely(remainder != 0 && !(flowset_length % 4 == 0 && remainder < 4))) {
            LOG_ERROR("%s %d %s: Flowset %d data length %lu not divisible by record size %lu — template mismatch, queuing\n",
                      __FILE__, __LINE__, __func__, template_id, flowset_data_len, total_record_size);
            enqueue_pending_flowset(hkey,
                                    (const uint8_t *)(args->data + flowset_base),
                                    flowset_length,
                                    args->exporter,
                                    args->now,
                                    header->SysUptime,
                                    header->unix_secs,
                                    header->package_sequence,
                                    header->source_id,
                                    args->flags,
                                    args->frame_number);
            goto skip_v9_record_pass;
        }

        while (pos + total_record_size <= flowset_length) {
          if (record_counter >= 60) {
            LOG_ERROR("%s %d %s: Too many records in FlowSet (> 60), truncating\n", __FILE__, __LINE__, __func__);
            break;
          }
#ifdef CNETFLOW_DEBUG_BUILD
          fprintf(stdout, "exporter: %s template: %d record_no: %d field_count: %d",
                  ip_int_to_str(args->exporter), template_id, record_counter + 1, field_count);
#endif
          for (size_t count = 2; count < field_count * 2 + 2; count = count + 2) {

            // CRITICAL FIX: Validate pointer is within packet bounds before accessing
            size_t pointer_offset = (size_t) pointer - (size_t) args->data;
            if (unlikely(pointer_offset >= total_packet_length)) {
              LOG_ERROR("%s %d %s: pointer offset %lu exceeds packet length %lu\n", __FILE__, __LINE__, __func__,
                        pointer_offset, total_packet_length);
              goto cleanup_template_and_unlock;
            }

            uint16_t field_type = template_hashmap[count];
            swap_endianness(&field_type, sizeof(field_type));
            if (unlikely(field_type >= (sizeof(ipfix_field_types) / sizeof(ipfix_field_type_t)))) {
              goto cleanup_template_and_unlock;
            }
            uint16_t field_length = template_hashmap[count + 1];
            swap_endianness(&field_length, sizeof(field_length));

            // Validate we have enough space for this field
            if (unlikely(pointer_offset + field_length > total_packet_length)) {
              LOG_ERROR("%s %d %s: field at offset %lu length %u exceeds packet bounds\n", __FILE__, __LINE__, __func__,
                        pointer_offset, field_length);
              if (has_padding) {
                pos = flowset_length; // Force outer while loop to terminate
                break;
              }
              goto cleanup_template_and_unlock;
            }

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

            switch (record_length) {
              case 1:
                tmp8 = (uint8_t *) pointer;
                val_tmp8 = *tmp8;
                break;
              case 2:
                tmp16 = (uint16_t *) pointer;
                val_tmp16 = *tmp16;
                swap_endianness(&val_tmp16, sizeof(val_tmp16));
                break;
              case 4:
                tmp32 = (uint32_t *) pointer;
                val_tmp32 = *tmp32;
                swap_endianness(&val_tmp32, sizeof(val_tmp32));
                break;
              case 6:
                tmp64 = (uint64_t *) pointer;
                val_tmp64 = *tmp64;
                swap_endianness(&val_tmp64, sizeof(val_tmp64));
                val_tmp64 &= 0x0000ffffffffffff;
                break;
              case 8:
                tmp64 = (uint64_t *) pointer;
                val_tmp64 = *tmp64;
                swap_endianness(&val_tmp64, sizeof(val_tmp64));
                break;
              case 16:
                tmp128 = (uint128_t *) pointer;
                memcpy(&val_tmp128, pointer, sizeof(uint128_t));
                swap_endianness(&val_tmp128, sizeof(val_tmp128));
                break;
            }

            // Process field based on IPFIX field type (same as NetFlow v9)
            switch (field_type) {
              case IPFIX_FT_FLOWENDSYSUPTIME:
                if (record_length == 4) {
                  val_tmp32 = val_tmp32 / 1000 + diff;
                  flows_to_insert.records[record_counter].Last = val_tmp32;
                } else if (record_length == 8) {
                  val_tmp64 = val_tmp64 / 1000 + diff;
                  uint32_t val32 = (uint32_t) val_tmp64;
                  flows_to_insert.records[record_counter].Last = val32;
                } else {
                  flows_to_insert.records[record_counter].Last = 0;
                }
                break;
              case IPFIX_FT_FLOWSTARTSYSUPTIME:
                if (record_length == 4) {
                  val_tmp32 = val_tmp32 / 1000 + diff;
                  flows_to_insert.records[record_counter].First = val_tmp32;
                } else if (record_length == 8) {
                  val_tmp64 = val_tmp64 / 1000 + diff;
                  uint32_t val32 = (uint32_t) val_tmp64;
                  flows_to_insert.records[record_counter].First = val32;
                } else {
                  flows_to_insert.records[record_counter].First = 0;
                }
                break;
              case IPFIX_FT_FLOWSTARTMILLISECONDS:
                val_tmp64 = val_tmp64 / 1000 + diff;
                {
                  uint32_t val32 = (uint32_t) val_tmp64;
                  flows_to_insert.records[record_counter].First = val32;
                }
                break;
              case IPFIX_FT_FLOWENDMILLISECONDS:
                val_tmp64 = val_tmp64 / 1000 + diff;
                {
                  uint32_t val32 = (uint32_t) val_tmp64;
                  flows_to_insert.records[record_counter].Last = val32;
                }
                break;
              case IPFIX_FT_IPVERSION:
                switch (val_tmp8) {
                  case 4:
                    is_ipv6 = 0;
                    flows_to_insert.records[record_counter].ip_version = 4;
                    break;
                  case 6:
                    is_ipv6 = 1;
                    flows_to_insert.records[record_counter].ip_version = 6;
                    break;
                  default:
                    is_ipv6 = 0;
                    flows_to_insert.records[record_counter].ip_version = 4;
                    break;
                }
                break;
              case IPFIX_FT_SOURCEIPV4ADDRESS:
                flows_to_insert.records[record_counter].srcaddr = val_tmp32;
                flows_to_insert.records[record_counter].ip_version = 4;
                break;
              case IPFIX_FT_DESTINATIONIPV4ADDRESS:
                flows_to_insert.records[record_counter].dstaddr = val_tmp32;
                break;
              case IPFIX_FT_SOURCEIPV6ADDRESS:
                flows_to_insert.records[record_counter].srcaddr = val_tmp128;
                flows_to_insert.records[record_counter].ip_version = 6;
                is_ipv6 = 1;
                break;
              case IPFIX_FT_DESTINATIONIPV6ADDRESS:
                flows_to_insert.records[record_counter].dstaddr = val_tmp128;
                is_ipv6 = 1;
                break;
              case IPFIX_FT_OCTETDELTACOUNT:
                switch (record_length) {
                  case 4:
                    flows_to_insert.records[record_counter].dOctets = ((uint64_t) val_tmp32);
                    break;
                  case 8:
                    flows_to_insert.records[record_counter].dOctets = (uint64_t) val_tmp64;
                    break;
                  default:
                    flows_to_insert.records[record_counter].dOctets = 0;
                    break;
                }
                break;
              case IPFIX_FT_PACKETDELTACOUNT:
                switch (record_length) {
                  case 4:
                    flows_to_insert.records[record_counter].dPkts = ((uint64_t) val_tmp32);
                    break;
                  case 8:
                    flows_to_insert.records[record_counter].dPkts = (uint64_t) val_tmp64;
                    break;
                  default:
                    flows_to_insert.records[record_counter].dPkts = 0;
                    break;
                }
                break;
              case IPFIX_FT_DESTINATIONTRANSPORTPORT:
              case IPFIX_FT_TCPDESTINATIONPORT:
              case IPFIX_FT_UDPDESTINATIONPORT:
                switch (record_length) {
                  case 2:
                    flows_to_insert.records[record_counter].dstport = (uint16_t) val_tmp16;
                    break;
                  case 4:
                    flows_to_insert.records[record_counter].dstport = (uint16_t) ((val_tmp32));
                    break;
                  default:
                    flows_to_insert.records[record_counter].dstport = 0;
                    break;
                }
                break;
              case IPFIX_FT_SOURCETRANSPORTPORT:
              case IPFIX_FT_TCPSOURCEPORT:
              case IPFIX_FT_UDPSOURCEPORT:
                switch (record_length) {
                  case 2:
                    flows_to_insert.records[record_counter].srcport = (uint16_t) val_tmp16;
                    break;
                  case 4:
                    flows_to_insert.records[record_counter].srcport = (uint16_t) ((val_tmp32));
                    break;
                  default:
                    flows_to_insert.records[record_counter].srcport = 0;
                    break;
                }
                break;
              case IPFIX_FT_PROTOCOLIDENTIFIER:
                flows_to_insert.records[record_counter].prot = val_tmp8;
                break;
              case IPFIX_FT_INGRESSINTERFACE:
                switch (record_length) {
                  case 2:
                    flows_to_insert.records[record_counter].input = val_tmp16;
                    break;
                  case 4:
                    flows_to_insert.records[record_counter].input = (uint16_t) ((val_tmp32));
                    break;
                  default:
                    flows_to_insert.records[record_counter].input = 0;
                    break;
                }
                break;
              case IPFIX_FT_EGRESSINTERFACE:
                switch (record_length) {
                  case 2:
                    flows_to_insert.records[record_counter].output = val_tmp16;
                    break;
                  case 4:
                    flows_to_insert.records[record_counter].output = (uint16_t) ((val_tmp32));
                    break;
                  default:
                    flows_to_insert.records[record_counter].output = 0;
                    break;
                }
                break;
              case IPFIX_FT_BGPSOURCEASNUMBER:
                switch (record_length) {
                  case 2:
                    flows_to_insert.records[record_counter].src_as = ((uint32_t) val_tmp16);
                    break;
                  case 4:
                    flows_to_insert.records[record_counter].src_as = val_tmp32;
                    break;
                  default:
                    flows_to_insert.records[record_counter].src_as = 0;
                    break;
                }
                break;
              case IPFIX_FT_BGPDESTINATIONASNUMBER:
                switch (record_length) {
                  case 2:
                    flows_to_insert.records[record_counter].dst_as = ((uint32_t) val_tmp16);
                    break;
                  case 4:
                    flows_to_insert.records[record_counter].dst_as = val_tmp32;
                    break;
                  default:
                    flows_to_insert.records[record_counter].dst_as = 0;
                    break;
                }
                break;
              case IPFIX_FT_BGPNEXTHOPIPV4ADDRESS:
                flows_to_insert.records[record_counter].nexthop = val_tmp32;
                break;
              case IPFIX_FT_BGPNEXTHOPIPV6ADDRESS:
                flows_to_insert.records[record_counter].nexthop = val_tmp128;
                is_ipv6 = 1;
                break;
              case IPFIX_FT_TCPCONTROLBITS:
                flows_to_insert.records[record_counter].tcp_flags = val_tmp8;
                break;
              case IPFIX_FT_IPCLASSOFSERVICE:
                flows_to_insert.records[record_counter].tos = val_tmp8;
                break;
              case IPFIX_FT_SOURCEIPV4PREFIXLENGTH:
                flows_to_insert.records[record_counter].src_mask = val_tmp8;
                break;
              case IPFIX_FT_DESTINATIONIPV4PREFIXLENGTH:
                flows_to_insert.records[record_counter].dst_mask = val_tmp8;
                break;
              case IPFIX_FT_SOURCEIPV6PREFIXLENGTH:
                flows_to_insert.records[record_counter].src_mask = val_tmp8;
                break;
              case IPFIX_FT_DESTINATIONIPV6PREFIXLENGTH:
                flows_to_insert.records[record_counter].dst_mask = val_tmp8;
                break;
              default:
                break;
            }

            pointer += record_length;
            pos += record_length;
          }

          if (flows_to_insert.records[record_counter].Last != 0 &&
              flows_to_insert.records[record_counter].First != 0) {
            uint32_t duration =
                flows_to_insert.records[record_counter].Last - flows_to_insert.records[record_counter].First;
            flows_to_insert.records[record_counter].Last = now;
            flows_to_insert.records[record_counter].First = now - duration;
          }
          if (!is_ipv6) {
            swap_src_dst_v9_ipv4(&flows_to_insert.records[record_counter]);
#ifdef CNETFLOW_DEBUG_BUILD
            printf_v9(stderr, &flows_to_insert, record_counter, args->frame_number, template_id, flowset_id);
#endif
          } else {
            LOG_ERROR("ipv6 not supported at the moment...\n");
          }

          local_v9_records++;

          if (flows_to_insert.records[record_counter].input != 0) {
            metrics_track_interface(args->exporter, flows_to_insert.records[record_counter].input);
          }
          if (flows_to_insert.records[record_counter].output != 0) {
            metrics_track_interface(args->exporter, flows_to_insert.records[record_counter].output);
          }

          record_counter++;
        }

#ifdef ENABLE_METRICS
        if (local_v9_records > 0) {
          metrics_inc_v9_records_received_batch(local_v9_records);
        }
#endif

        flows_to_insert.header.count = record_counter;

        flows_to_insert.header.SysUptime = header->SysUptime;
        flows_to_insert.header.unix_secs = header->unix_secs;
        flows_to_insert.header.unix_nsecs = 0;
        flows_to_insert.header.flow_sequence = header->package_sequence;
        flows_to_insert.header.sampling_interval = header->source_id;

        uint32_t exporter_host = args->exporter;
        swap_endianness((void *) &exporter_host, sizeof(exporter_host));

        LOG_INFO("%s %d %s Inserting %lu v9 flows\n", __FILE__, __LINE__, __func__, record_counter);
        total_flows_in_packet += record_counter;
        collector_inc_received_flows(record_counter);
        if (args->flags & 2) {
            for (size_t i = 0; i < record_counter; i++) {
                uint32_t saddr = flows_to_insert.records[i].srcaddr;
                uint32_t daddr = flows_to_insert.records[i].dstaddr;
                if (saddr == 0 || daddr == 0) {
                    continue;
                }
                if ((saddr >> 24) == 0 || (daddr >> 24) == 0) {
                    continue;
                }
                printf_v9(stdout, &flows_to_insert, i, args->frame_number, template_id, flowset_id);
            }
        } else {
            insert_flows(exporter_host, &flows_to_insert);
        }
      }
      skip_v9_record_pass:;
    } else if (flowset_id == 1) {
    } else if (flowset_id > 1 && flowset_id < 256) {
      LOG_ERROR("%s %d %s this is a reserved flowset: %d\n", __FILE__, __LINE__, __func__, flowset_id);
    } else {
      LOG_ERROR("%s %d %s this should not happen\n", __FILE__, __LINE__, __func__);
      goto cleanup_template_and_unlock;
    }
    record_counter = 0;
    flowset_base = flowset_end;
  }

cleanup_template_and_unlock:

  uv_mutex_unlock(&v9_parse_mutex);
  args->processed_flows = total_flows_in_packet;
  args->status = collector_data_status_done;

  return NULL;
}

// ---------------------------------------------------------------------------
// decode_v9_data_flowset — decode one raw data flowset using the given template.
// flowset_data points to the raw bytes starting at the flowset_id field.
// flowset_length is the full length (including 4-byte header).
// This is called both from the live parse path and when replaying pending flowsets.
// ---------------------------------------------------------------------------
static void decode_v9_data_flowset(const uint8_t *flowset_data,
                                    uint16_t flowset_length,
                                    uint16_t *template_hashmap,
                                    uint32_t exporter,
                                    uint32_t now,
                                    uint32_t SysUptime,
                                    uint32_t unix_secs,
                                    uint32_t package_sequence,
                                    uint32_t source_id,
                                    uint32_t flags,
                                    uint32_t frame_number) {
  (void)unix_secs; (void)package_sequence; (void)source_id; // used by caller context only
  (void)frame_number;

  uint16_t field_count = template_hashmap[1];
  swap_endianness(&field_count, sizeof(field_count));
  
  uint16_t template_id = template_hashmap[0];
  swap_endianness(&template_id, sizeof(template_id));
  uint16_t flowset_id = template_id;

  // Compute total size of one record based on template fields
  size_t total_record_size = 0;
  for (size_t count = 2; count < field_count * 2 + 2; count += 2) {
    uint16_t flen = template_hashmap[count + 1];
    swap_endianness(&flen, sizeof(flen));
    total_record_size += flen;
  }
  if (total_record_size == 0) return;

  size_t flowset_data_len = (flowset_length > 4) ? (flowset_length - 4) : 0;
  size_t remainder = flowset_data_len % total_record_size;
  if (remainder != 0 && !(flowset_length % 4 == 0 && remainder < 4)) return;

  uint32_t diff = now - (uint32_t)(SysUptime / 1000);

  netflow_v9_uint128_flowset_t flows_to_insert;
  memset(&flows_to_insert, 0, sizeof(flows_to_insert));
  int is_ipv6 = 0;
  size_t record_counter = 0;
  uint64_t local_v9_records = 0;

  // The data records start at byte offset 4 (after flowset_id + length)
  const uint8_t *record_base = flowset_data + 4;
  size_t pos = 0;

  metrics_track_exporter(exporter);
  metrics_inc_flowsets(1);

  while (pos + total_record_size <= flowset_data_len) {
    if (record_counter >= 60) break;

    const uint8_t *pointer = record_base + pos;

    for (size_t count = 2; count < field_count * 2 + 2; count += 2) {
      uint16_t field_type = template_hashmap[count];
      swap_endianness(&field_type, sizeof(field_type));
      if (unlikely(field_type >= (sizeof(ipfix_field_types) / sizeof(ipfix_field_type_t))))
        goto decode_done;

      uint16_t field_length = template_hashmap[count + 1];
      swap_endianness(&field_length, sizeof(field_length));

      uint16_t record_length = field_length;
      uint8_t  val_tmp8  = 0;
      uint16_t val_tmp16 = 0;
      uint32_t val_tmp32 = 0;
      uint64_t val_tmp64 = 0;
      uint128_t val_tmp128 = 0;

      switch (record_length) {
        case 1:  val_tmp8  = *(const uint8_t *)pointer; break;
        case 2:  memcpy(&val_tmp16, pointer, 2); swap_endianness(&val_tmp16, 2); break;
        case 4:  memcpy(&val_tmp32, pointer, 4); swap_endianness(&val_tmp32, 4); break;
        case 6:  memcpy(&val_tmp64, pointer, 6); swap_endianness(&val_tmp64, 8); val_tmp64 &= 0x0000ffffffffffffULL; break;
        case 8:  memcpy(&val_tmp64, pointer, 8); swap_endianness(&val_tmp64, 8); break;
        case 16: memcpy(&val_tmp128, pointer, 16); swap_endianness(&val_tmp128, 16); break;
        default: break;
      }

      switch (field_type) {
        case IPFIX_FT_FLOWENDSYSUPTIME:
          flows_to_insert.records[record_counter].Last =
            (record_length == 4) ? val_tmp32 / 1000 + diff
            : (record_length == 8) ? (uint32_t)(val_tmp64 / 1000 + diff) : 0;
          break;
        case IPFIX_FT_FLOWSTARTSYSUPTIME:
          flows_to_insert.records[record_counter].First =
            (record_length == 4) ? val_tmp32 / 1000 + diff
            : (record_length == 8) ? (uint32_t)(val_tmp64 / 1000 + diff) : 0;
          break;
        case IPFIX_FT_FLOWSTARTMILLISECONDS:
          flows_to_insert.records[record_counter].First = (uint32_t)(val_tmp64 / 1000 + diff);
          break;
        case IPFIX_FT_FLOWENDMILLISECONDS:
          flows_to_insert.records[record_counter].Last = (uint32_t)(val_tmp64 / 1000 + diff);
          break;
        case IPFIX_FT_SOURCEIPV4ADDRESS:
          flows_to_insert.records[record_counter].srcaddr = val_tmp32;
          flows_to_insert.records[record_counter].ip_version = 4;
          break;
        case IPFIX_FT_DESTINATIONIPV4ADDRESS:
          flows_to_insert.records[record_counter].dstaddr = val_tmp32;
          break;
        case IPFIX_FT_SOURCEIPV6ADDRESS:
          flows_to_insert.records[record_counter].srcaddr = val_tmp128;
          flows_to_insert.records[record_counter].ip_version = 6;
          is_ipv6 = 1;
          break;
        case IPFIX_FT_DESTINATIONIPV6ADDRESS:
          flows_to_insert.records[record_counter].dstaddr = val_tmp128;
          is_ipv6 = 1;
          break;
        case IPFIX_FT_OCTETDELTACOUNT:
          flows_to_insert.records[record_counter].dOctets =
            (record_length == 4) ? (uint64_t)val_tmp32 : (uint64_t)val_tmp64;
          break;
        case IPFIX_FT_PACKETDELTACOUNT:
          flows_to_insert.records[record_counter].dPkts =
            (record_length == 4) ? (uint64_t)val_tmp32 : (uint64_t)val_tmp64;
          break;
        case IPFIX_FT_SOURCETRANSPORTPORT:
        case IPFIX_FT_TCPSOURCEPORT:
        case IPFIX_FT_UDPSOURCEPORT:
          flows_to_insert.records[record_counter].srcport = val_tmp16;
          break;
        case IPFIX_FT_DESTINATIONTRANSPORTPORT:
        case IPFIX_FT_TCPDESTINATIONPORT:
        case IPFIX_FT_UDPDESTINATIONPORT:
          flows_to_insert.records[record_counter].dstport = val_tmp16;
          break;
        case IPFIX_FT_PROTOCOLIDENTIFIER:
          flows_to_insert.records[record_counter].prot = val_tmp8;
          break;
        case IPFIX_FT_INGRESSINTERFACE:
          flows_to_insert.records[record_counter].input =
            (record_length == 2) ? (uint32_t)val_tmp16 : val_tmp32;
          break;
        case IPFIX_FT_EGRESSINTERFACE:
          flows_to_insert.records[record_counter].output =
            (record_length == 2) ? (uint32_t)val_tmp16 : val_tmp32;
          break;
        case IPFIX_FT_BGPSOURCEASNUMBER:
          flows_to_insert.records[record_counter].src_as =
            (record_length == 2) ? (uint32_t)val_tmp16 : val_tmp32;
          break;
        case IPFIX_FT_BGPDESTINATIONASNUMBER:
          flows_to_insert.records[record_counter].dst_as =
            (record_length == 2) ? (uint32_t)val_tmp16 : val_tmp32;
          break;
        case IPFIX_FT_BGPNEXTHOPIPV4ADDRESS:
          flows_to_insert.records[record_counter].nexthop = val_tmp32;
          break;
        case IPFIX_FT_TCPCONTROLBITS:
          flows_to_insert.records[record_counter].tcp_flags = val_tmp8;
          break;
        case IPFIX_FT_IPCLASSOFSERVICE:
          flows_to_insert.records[record_counter].tos = val_tmp8;
          break;
        case IPFIX_FT_SOURCEIPV4PREFIXLENGTH:
        case IPFIX_FT_SOURCEIPV6PREFIXLENGTH:
          flows_to_insert.records[record_counter].src_mask = val_tmp8;
          break;
        case IPFIX_FT_DESTINATIONIPV4PREFIXLENGTH:
        case IPFIX_FT_DESTINATIONIPV6PREFIXLENGTH:
          flows_to_insert.records[record_counter].dst_mask = val_tmp8;
          break;
        default:
          break;
      }

      pointer += record_length;
    }

    // Fix up timestamps
    if (flows_to_insert.records[record_counter].Last != 0 &&
        flows_to_insert.records[record_counter].First != 0) {
      uint32_t duration = flows_to_insert.records[record_counter].Last
                        - flows_to_insert.records[record_counter].First;
      flows_to_insert.records[record_counter].Last  = now;
      flows_to_insert.records[record_counter].First = now - duration;
    }

    if (!is_ipv6) {
      swap_src_dst_v9_ipv4(&flows_to_insert.records[record_counter]);
    }

    if (flows_to_insert.records[record_counter].input != 0)
      metrics_track_interface(exporter, flows_to_insert.records[record_counter].input);
    if (flows_to_insert.records[record_counter].output != 0)
      metrics_track_interface(exporter, flows_to_insert.records[record_counter].output);

    local_v9_records++;
    record_counter++;
    pos += total_record_size;
  }

decode_done:
#ifdef ENABLE_METRICS
  if (local_v9_records > 0)
    metrics_inc_v9_records_received_batch(local_v9_records);
#endif

  flows_to_insert.header.count = record_counter;
  flows_to_insert.header.SysUptime    = SysUptime;
  flows_to_insert.header.unix_secs    = unix_secs;
  flows_to_insert.header.unix_nsecs   = 0;
  flows_to_insert.header.flow_sequence     = package_sequence;
  flows_to_insert.header.sampling_interval = source_id;

  uint32_t exporter_host = exporter;
  swap_endianness(&exporter_host, sizeof(exporter_host));

  collector_inc_received_flows(record_counter);

  if (flags & 2) {
    for (size_t i = 0; i < record_counter; i++) {
      uint32_t saddr = flows_to_insert.records[i].srcaddr;
      uint32_t daddr = flows_to_insert.records[i].dstaddr;
      if ((saddr >> 24) == 0 || (daddr >> 24) == 0) continue;
      printf_v9(stdout, &flows_to_insert, i, frame_number, template_id, flowset_id);
    }
  } else {
    insert_flows(exporter_host, &flows_to_insert);
  }
}





void copy_v9_to_flow(const netflow_v9_flowset_t * restrict in, netflow_v9_uint128_flowset_t * restrict out, int is_ipv6, uint8_t *dump) {
  // fprintf(stderr, "%s %d %s copy_v9_to_flow entry\n", __FILE__, __LINE__, __func__);
  out->header.count = in->header.count;
  out->header.SysUptime = in->header.SysUptime;
  out->header.unix_secs = in->header.unix_secs;
  out->header.unix_nsecs = in->header.unix_nsecs;
  out->header.flow_sequence = in->header.flow_sequence;
  out->header.sampling_interval = in->header.sampling_interval;
  for (int i = 0; i < in->header.count; i++) {
    // Non-destructive copy & swap
    out->records[i].srcport = in->records[i].srcport;
    // swap_endianness(&out->records[i].srcport, sizeof(out->records[i].srcport));

    out->records[i].dstport = in->records[i].dstport;
    // swap_endianness(&out->records[i].dstport, sizeof(out->records[i].dstport));

    out->records[i].dPkts = in->records[i].dPkts;
    // swap_endianness(&out->records[i].dPkts, sizeof(out->records[i].dPkts));

    out->records[i].dOctets = in->records[i].dOctets;
    // swap_endianness(&out->records[i].dOctets, sizeof(out->records[i].dOctets));

    // First and Last are already Host Order from parse_v9
    out->records[i].First = in->records[i].First;
    out->records[i].Last = in->records[i].Last;

    out->records[i].input = in->records[i].input;
    // swap_endianness(&out->records[i].input, sizeof(out->records[i].input));

    out->records[i].output = in->records[i].output;
    // swap_endianness(&out->records[i].output, sizeof(out->records[i].output));

    out->records[i].src_as = in->records[i].src_as;
    // swap_endianness(&out->records[i].src_as, sizeof(out->records[i].src_as));

    out->records[i].dst_as = in->records[i].dst_as;
    // swap_endianness(&out->records[i].dst_as, sizeof(out->records[i].dst_as));

    out->records[i].src_mask = in->records[i].src_mask;
    // swap_endianness(&out->records[i].src_mask, sizeof(out->records[i].src_mask));

    out->records[i].dst_mask = in->records[i].dst_mask;
    // swap_endianness(&out->records[i].dst_mask, sizeof(out->records[i].dst_mask));

    out->records[i].tcp_flags = in->records[i].tcp_flags;
    out->records[i].prot = in->records[i].prot;
    out->records[i].tos = in->records[i].tos;

    if (is_ipv6) {
      out->records[i].srcaddr = in->records[i].ipv6srcaddr;
      // swap_endianness(&out->records[i].srcaddr, sizeof(out->records[i].srcaddr));

      out->records[i].dstaddr = in->records[i].ipv6dstaddr;
      // swap_endianness(&out->records[i].dstaddr, sizeof(out->records[i].dstaddr));

      out->records[i].nexthop = in->records[i].ipv6nexthop;
      // swap_endianness(&out->records[i].nexthop, sizeof(out->records[i].nexthop));

      out->records[i].ip_version = 6;
    } else {
      uint32_t tmp;

      tmp = in->records[i].srcaddr;
      // swap_endianness(&tmp, sizeof(tmp));
      out->records[i].srcaddr = tmp;

      tmp = in->records[i].dstaddr;
      // swap_endianness(&tmp, sizeof(tmp));
      out->records[i].dstaddr = tmp;

      tmp = in->records[i].nexthop;
      // swap_endianness(&tmp, sizeof(tmp));
      out->records[i].nexthop = tmp;

      out->records[i].ip_version = 4;
    }
  }
  // fprintf(stderr, "%s %d %s copy_v9_to_flow return\n", __FILE__, __LINE__, __func__);
}
