import re
import os

files_to_modify = ['netflow_v9.c', 'netflow_ipfix.c', 'netflow_v5.c']

for filename in files_to_modify:
    if not os.path.exists(filename):
        continue
    with open(filename, 'r') as f:
        content = f.read()

    # 1. Replace the unsafe pointer cast + assignment + swap_endianness pattern
    # Pattern: 
    # tmp16 = (uint16_t *) pointer;
    # val_tmp16 = *tmp16;
    # swap_endianness(&val_tmp16, sizeof(val_tmp16));
    
    # 16-bit
    content = re.sub(
        r'tmp16\s*=\s*\(uint16_t\s*\*\)\s*pointer;\s*val_tmp16\s*=\s*\*tmp16;\s*swap_endianness\(&val_tmp16,\s*sizeof\(val_tmp16\)\);',
        r'memcpy(&val_tmp16, pointer, sizeof(val_tmp16));\n                val_tmp16 = swap_endian_16(val_tmp16);',
        content
    )
    # 32-bit
    content = re.sub(
        r'tmp32\s*=\s*\(uint32_t\s*\*\)\s*pointer;\s*val_tmp32\s*=\s*\*tmp32;\s*swap_endianness\(&val_tmp32,\s*sizeof\(val_tmp32\)\);',
        r'memcpy(&val_tmp32, pointer, sizeof(val_tmp32));\n                val_tmp32 = swap_endian_32(val_tmp32);',
        content
    )
    # 64-bit
    content = re.sub(
        r'tmp64\s*=\s*\(uint64_t\s*\*\)\s*pointer;\s*val_tmp64\s*=\s*\*tmp64;\s*swap_endianness\(&val_tmp64,\s*sizeof\(val_tmp64\)\);',
        r'memcpy(&val_tmp64, pointer, sizeof(val_tmp64));\n                val_tmp64 = swap_endian_64(val_tmp64);',
        content
    )
    # 128-bit
    content = re.sub(
        r'tmp128\s*=\s*\(uint128_t\s*\*\)\s*pointer;\s*memcpy\(&val_tmp128,\s*pointer,\s*sizeof\(uint128_t\)\);\s*swap_endianness\(&val_tmp128,\s*sizeof\(val_tmp128\)\);',
        r'memcpy(&val_tmp128, pointer, sizeof(val_tmp128));\n                val_tmp128 = swap_endian_128(val_tmp128);',
        content
    )

    # 2. General struct member swaps like swap_endianness((void *) &(header->version), sizeof(header->version));
    # We will replace them with header->version = swap_endian_16(header->version);
    
    # We can use regex to find: swap_endianness(?:\(\s*void\s*\*\s*\))?\s*&\(([^)]+)\),\s*sizeof\([^)]+\)\);
    # Since we can't easily know if it's 16 or 32 bit, let's do this manually for the headers.
    
    # header->version (16)
    content = re.sub(r'swap_endianness\(\(void \*\) &\(([^>]+->version)\), sizeof\([^)]+\)\);', r'\1 = swap_endian_16(\1);', content)
    # header->count (16)
    content = re.sub(r'swap_endianness\(\(void \*\) &\(([^>]+->count)\), sizeof\([^)]+\)\);', r'\1 = swap_endian_16(\1);', content)
    # header->SysUptime (32)
    content = re.sub(r'swap_endianness\(\(void \*\) &\(([^>]+->SysUptime)\), sizeof\([^)]+\)\);', r'\1 = swap_endian_32(\1);', content)
    # header->unix_secs (32)
    content = re.sub(r'swap_endianness\(\(void \*\) &\(([^>]+->unix_secs)\), sizeof\([^)]+\)\);', r'\1 = swap_endian_32(\1);', content)
    # header->unix_nsecs (32)
    content = re.sub(r'swap_endianness\(\(void \*\) &\(([^>]+->unix_nsecs)\), sizeof\([^)]+\)\);', r'\1 = swap_endian_32(\1);', content)
    # header->flow_sequence (32)
    content = re.sub(r'swap_endianness\(\(void \*\) &\(([^>]+->flow_sequence)\), sizeof\([^)]+\)\);', r'\1 = swap_endian_32(\1);', content)
    # header->package_sequence (32)
    content = re.sub(r'swap_endianness\(\(void \*\) &\(([^>]+->package_sequence)\), sizeof\([^)]+\)\);', r'\1 = swap_endian_32(\1);', content)
    # header->source_id (32)
    content = re.sub(r'swap_endianness\(\(void \*\) &\(([^>]+->source_id)\), sizeof\([^)]+\)\);', r'\1 = swap_endian_32(\1);', content)
    
    # flowset->template.flowset_id (16)
    content = re.sub(r'swap_endianness\(&([^>]+->template.flowset_id), sizeof\([^)]+\)\);', r'\1 = swap_endian_16(\1);', content)
    # flowset->template.length (16)
    content = re.sub(r'swap_endianness\(&([^>]+->template.length), sizeof\([^)]+\)\);', r'\1 = swap_endian_16(\1);', content)
    
    # template_id (16)
    content = re.sub(r'swap_endianness\(&template_id, sizeof\(template_id\)\);', r'template_id = swap_endian_16(template_id);', content)
    # field_count (16)
    content = re.sub(r'swap_endianness\(&field_count, sizeof\(field_count\)\);', r'field_count = swap_endian_16(field_count);', content)
    
    # t (16)
    content = re.sub(r'swap_endianness\(&t, sizeof\(t\)\);', r't = swap_endian_16(t);', content)
    # l (16)
    content = re.sub(r'swap_endianness\(&l, sizeof\(l\)\);', r'l = swap_endian_16(l);', content)

    # len (16)
    content = re.sub(r'swap_endianness\(&len, sizeof\(len\)\);', r'len = swap_endian_16(len);', content)

    # field_type (16)
    content = re.sub(r'swap_endianness\(&field_type, sizeof\(field_type\)\);', r'field_type = swap_endian_16(field_type);', content)
    # field_length (16)
    content = re.sub(r'swap_endianness\(&field_length, sizeof\(field_length\)\);', r'field_length = swap_endian_16(field_length);', content)
    
    # exporter_host (32)
    content = re.sub(r'swap_endianness\(\(void \*\) &exporter_host, sizeof\(exporter_host\)\);', r'exporter_host = swap_endian_32(exporter_host);', content)
    
    with open(filename, 'w') as f:
        f.write(content)
    print(f"Refactored {filename}")

# Fix db_clickhouse.c exporter swap
db_file = 'db_clickhouse.c'
with open(db_file, 'r') as f:
    content = f.read()
content = re.sub(r'swap_endianness\(&exporter, sizeof\(exporter\)\);', r'exporter = swap_endian_32(exporter);', content)
with open(db_file, 'w') as f:
    f.write(content)
print(f"Refactored {db_file}")

# Remove swap_endianness from netflow.h
netflow_h = 'netflow.h'
with open(netflow_h, 'r') as f:
    lines = f.readlines()

with open(netflow_h, 'w') as f:
    skip = False
    for line in lines:
        if '#if CNETFLOW_BIG_ENDIAN_ARCH' in line and lines[lines.index(line)+1].startswith('#define swap_endianness'):
            skip = True
        if skip and line.strip() == '#endif':
            skip = False
            continue
        if not skip:
            f.write(line)
print(f"Removed swap_endianness from {netflow_h}")

