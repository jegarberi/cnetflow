//
// Created by jon on 6/3/25.
//

#ifndef NETFLOW_IPFIX_H
#define NETFLOW_IPFIX_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "arena.h"
#include "collector.h"
#include "fields.h"
#include "hashmap.h"
#include "netflow.h"

#define ENTERPRISE_BIT = (2 << 31)

typedef struct {
  uint16_t field_type; // This field gives the number of fields in this template record. Because a template FlowSet may
                       // contain multiple template records, this field allows the parser to determine the end of the
                       // current template record and the start of the next.
  uint16_t field_length; // This numeric value represents the type of the field. The possible values of the field type
                         // are vendor specific. Cisco supplied values are consistent across all platforms that support
                         // NetFlow Version 9. At the time of the initial release of the NetFlow Version 9 code (and
                         // after any subsequent changes that could add new field-type definitions), Cisco provides a
                         // file that defines the known field types and their lengths... The currently defined field
                         // types are detailed in Table 6.
} netflow_ipfix_template_fields_t;


typedef struct {
  uint16_t value;
} netflow_ipfix_record_value_t;


typedef enum {
  IPFIX_System = 1,
  IPFIX_Interface = 2,
  IPFIX_Line_Card = 3,
  IPFIX_NetFlow_Cache = 4,
  IPFIX_Template = 5,
} netflow_ipfix_scope_field_type_enum;

enum {
  IPFIX_TEMPLATE_SET = 2,
  IPFIX_OPTION_SET = 3,
};

typedef struct {
  uint16_t template_id; // As a router generates different template FlowSets to match the type of NetFlow data it will
                        // be exporting, each template is given a unique ID. This uniqueness is local to the router that
                        // generated the template ID..Templates that define data record formats begin numbering at 256
                        // since 0-255 are reserved for FlowSet IDs.
  uint16_t field_count; // This field gives the number of fields in this template record. Because a template FlowSet may
                        // contain multiple template records, this field allows the parser to determine the end of the
                        // current template record and the start of the next.
  netflow_ipfix_template_fields_t
      fields[]; // This field contains the field definitions for the template record. The field definitions are
                // expressed as a series of TLV records. The first TLV record in the field definitions is always the
                // field type and length. The remaining TLV records are the field values. The field values are expressed
                // as a series of TLV records. The first TLV record in the field values is always the field type and
                // length. The remaining TLV records are the field values.
} netflow_ipfix_template_t;

typedef struct {
  uint16_t
      flowset_id; // The FlowSet ID is used to distinguish template records from data records. A template record always
                  // has a FlowSet ID in the range of 0-255. Currently, the template record that describes flow fields
                  // has a FlowSet ID of zero and the template record that describes option fields (described below) has
                  // a FlowSet ID of 1. A data record always has a nonzero FlowSet ID greater than 255.
  uint16_t length; // Length refers to the total length of this FlowSet. Because an individual template FlowSet may
                   // contain multiple template IDs (as illustrated above), the length value should be used to determine
                   // the position of the next FlowSet record, which could be either a template or a data
                   // FlowSet..Length is expressed in Type/Length/Value (TLV) format, meaning that the value includes
                   // the bytes used for the FlowSet ID and the length bytes themselves, as well as the combined lengths
                   // of all template records included in this FlowSet.
  netflow_ipfix_template_t templates[];
} netflow_ipfix_flow_header_template_t; // netflow_ipfix_flow_header_t;

typedef struct {
  uint16_t
      flowset_id; // A FlowSet ID precedes each group of records within a NetFlow Version 9 data FlowSet. The FlowSet ID
                  // maps to a (previously received) template ID. The collector and display applications should use the
                  // FlowSet ID to map the appropriate type and length to any field values that follow.
  uint16_t length; // This field gives the length of the data FlowSet. Length is expressed in TLV format, meaning that
                   // the value includes the bytes used for the FlowSet ID and the length bytes themselves, as well as
                   // the combined lengths of any included data records.
  netflow_ipfix_record_value_t record_value;
} netflow_ipfix_record_t;

typedef struct {
  uint16_t
      flowset_id; // The FlowSet ID is used to distinguish template records from data records. A template record always
                  // has a FlowSet ID of 1. A data record always has a nonzero FlowSet ID which is greater than 255.
  uint16_t length; // Length refers to the total length of this FlowSet. Because an individual template FlowSet may
                   // contain multiple template IDs (as illustrated above), the length value should be used to determine
                   // the position of the next FlowSet record, which could be either a template or a data
                   // FlowSet..Length is expressed in Type/Length/Value (TLV) format, meaning that the value includes
                   // the bytes used for the FlowSet ID and the length bytes themselves, as well as the combined lengths
                   // of all template records included in this FlowSet.
  uint32_t template_id; // As a router generates different template FlowSets to match the type of NetFlow data it will
                        // be exporting, each template is given a unique ID. This uniqueness is local to the router that
                        // generated the template ID. The Template ID is greater than 255. Template IDs inferior to 255
                        // are reserved.
  uint32_t option_scope_length; // This field gives the length in bytes of any scope fields contained in this options
                                // template (the use of scope is described below).
} netflow_ipfix_options_t;

typedef union {
  netflow_ipfix_flow_header_template_t template;
  netflow_ipfix_record_t record;
  netflow_ipfix_options_t option;
} flowset_union_ipfix_t;

typedef struct {
  uint16_t version; // The version of NetFlow records exported in this packet; for Version 9, this value is 0x0009
  uint16_t length; // Number of FlowSet records (both template and data) contained within this packet
  uint32_t ExportTime; // Time in milliseconds since this device was first booted
  uint32_t SequenceNumber; // Seconds since 0000 Coordinated Universal Time (UTC) 1970
  uint32_t ObsDomainId; // Incremental sequence counter of all export packets sent by this export device; this value is
                        // cumulative, and it can be used to identify whether any export packets have been missed

  flowset_union_ipfix_t flowsets[];
} netflow_ipfix_header_t;


void init_ipfix(arena_struct_t *arena, const size_t cap);
void *parse_ipfix(uv_work_t *req);
void copy_ipfix_to_flow(netflow_v9_flowset_t *, netflow_v9_uint128_flowset_t *, int);
#endif // NETFLOW_IPFIX_H
