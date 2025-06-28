//
// Created by jon on 6/3/25.
//

#ifndef NETFLOW_V9_H
#define NETFLOW_V9_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "arena.h"
#include "collector.h"
#include "db_psql.h"
#include "fields.h"
#include "hashmap.h"
#include "netflow.h"


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
} netflow_v9_template_fields_t;


typedef struct {
  uint16_t value;
} netflow_v9_record_value_t;


typedef enum {
  System = 1,
  Interface = 2,
  Line_Card = 3,
  NetFlow_Cache = 4,
  Template = 5,
} netflow_v9_scope_field_type_enum;


typedef struct {
  uint16_t template_id; // As a router generates different template FlowSets to match the type of NetFlow data it will
                        // be exporting, each template is given a unique ID. This uniqueness is local to the router that
                        // generated the template ID..Templates that define data record formats begin numbering at 256
                        // since 0-255 are reserved for FlowSet IDs.
  uint16_t field_count; // This field gives the number of fields in this template record. Because a template FlowSet may
                        // contain multiple template records, this field allows the parser to determine the end of the
                        // current template record and the start of the next.
  netflow_v9_template_fields_t
      fields[]; // This field contains the field definitions for the template record. The field definitions are
                // expressed as a series of TLV records. The first TLV record in the field definitions is always the
                // field type and length. The remaining TLV records are the field values. The field values are expressed
                // as a series of TLV records. The first TLV record in the field values is always the field type and
                // length. The remaining TLV records are the field values.
} netflow_v9_template_t;

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
  netflow_v9_template_t templates[];
} netflow_v9_flow_header_template_t; // netflow_v9_flow_header_t;

typedef struct {
  uint16_t
      flowset_id; // A FlowSet ID precedes each group of records within a NetFlow Version 9 data FlowSet. The FlowSet ID
                  // maps to a (previously received) template ID. The collector and display applications should use the
                  // FlowSet ID to map the appropriate type and length to any field values that follow.
  uint16_t length; // This field gives the length of the data FlowSet. Length is expressed in TLV format, meaning that
                   // the value includes the bytes used for the FlowSet ID and the length bytes themselves, as well as
                   // the combined lengths of any included data records.
  netflow_v9_record_value_t record_value;
} netflow_v9_record_t;

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
} netflow_v9_options_t;

typedef union {
  netflow_v9_flow_header_template_t template;
  netflow_v9_record_t record;
  netflow_v9_options_t option;
} flowset_union_t;

typedef struct {
  uint16_t version; // The version of NetFlow records exported in this packet; for Version 9, this value is 0x0009
  uint16_t count; // Number of FlowSet records (both template and data) contained within this packet
  uint32_t SysUptime; // Time in milliseconds since this device was first booted
  uint32_t unix_secs; // Seconds since 0000 Coordinated Universal Time (UTC) 1970
  uint32_t
      package_sequence; // Incremental sequence counter of all export packets sent by this export device; this value is
                        // cumulative, and it can be used to identify whether any export packets have been missed
  uint32_t
      source_id; // The Source ID field is a 32-bit value that is used to guarantee uniqueness for all flows exported
                 // from a particular device. (The Source ID field is the equivalent of the engine type and engine ID
                 // fields found in the NetFlow Version 5 and Version 8 headers). The format of this field is vendor
                 // specific. In the Cisco implementation, the first two bytes are reserved for future expansion, and
                 // will always be zero. Byte 3 provides uniqueness with respect to the routing engine on the exporting
                 // device. Byte 4 provides uniqueness with respect to the particular line card or Versatile Interface
                 // Processor on the exporting device. Collector devices should use the combination of the source IP
                 // address plus the Source ID field to associate an incoming NetFlow export packet with a unique
                 // instance of NetFlow on a particular device.
  flowset_union_t flowsets[];
} netflow_v9_header_t;


void init_v9(arena_struct_t *arena, const size_t cap);
void *parse_v9(uv_work_t *req);
#endif // NETFLOW_V9_H
