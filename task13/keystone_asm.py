#!/usr/bin/env python3
import keystone

# Specify the starting address
start_address = 0x1000

# Initialize Keystone with the x86 architecture in 64-bit mode
ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
assembly_code = None
curr_address = start_address

out_filename = "yoda_code.bin"
out_file = open(out_filename, "wb")

# Read the assembly code from a file
with open("yoda.asm", "r") as asm_file:
    for line in asm_file:
        parts = line.strip().split(";")
        
        if len(parts) != 2:
            print(f"Invalid line in the assembly file: {line}")
            continue

        try:
            byte_count = int(parts[0])
            assembly_code = parts[1]

            # Assemble the code
            assembled_code, _ = ks.asm(assembly_code, addr=curr_address)
            real_size = len(assembled_code)

            print("0x%x: %s" % (curr_address, assembly_code) )
            curr_address += real_size
            for byte in assembled_code:
                print(f"{byte:02X}", end=" ")
            print("\n")

            out_file.write(bytes(assembled_code))
            
            if byte_count != real_size:
                print("!!! Expected size: %d vs Real Size: %d" % (byte_count, len(assembled_code)) )
                while real_size < byte_count:
                    assembled_code, _ = ks.asm("nop", addr=curr_address)
                    real_size += len(assembled_code)
                    curr_address += len(assembled_code)
                    out_file.write(bytes(assembled_code))

        except keystone.KsError as e:
            print(f"Assembly failed: {e}")
            
print("\nAssembled code has been written to '%s'." % out_filename)