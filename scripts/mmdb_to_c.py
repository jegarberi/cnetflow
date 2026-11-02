#!/usr/bin/env python3
import sys
import os

def generate_c_array(file_path, array_name, output_h, output_c):
    with open(file_path, "rb") as f:
        data = f.read()

    # Generate .h file
    with open(output_h, "w") as f:
        f.write(f"#ifndef {array_name.upper()}_H\n")
        f.write(f"#define {array_name.upper()}_H\n\n")
        f.write(f"extern const unsigned char {array_name}[];\n")
        f.write(f"extern const unsigned int {array_name}_len;\n\n")
        f.write(f"#endif\n")

    # Generate .c file
    with open(output_c, "w") as f:
        f.write(f"#include \"{os.path.basename(output_h)}\"\n\n")
        f.write(f"const unsigned char {array_name}[] = {{\n")
        
        # Write bytes
        bytes_per_line = 12
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i+bytes_per_line]
            hex_str = ", ".join([f"0x{b:02x}" for b in chunk])
            f.write(f"    {hex_str}")
            if i + bytes_per_line < len(data):
                f.write(",")
            f.write("\n")
            
        f.write(f"}};\n")
        f.write(f"const unsigned int {array_name}_len = {len(data)};\n")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: mmdb_to_c.py <input.mmdb> <array_name> <output.h> <output.c>")
        sys.exit(1)
        
    generate_c_array(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
