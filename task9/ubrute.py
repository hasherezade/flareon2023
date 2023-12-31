from unicorn import *
from unicorn.x86_const import *
import random
import string
import itertools

# memory address where emulation starts
ADDRESS = 0x1000
DATA_ADDR = 0x2a5c

def dump_mem(mu, addr):
    tmp = mu.mem_read(addr, 16) #0x2A64
    for i in tmp:
        print("%x" %(i))

def make_key2(key):
    rkey = ""
    for k in key:
    	rkey += "0"
    	rkey += k
    return rkey

def get_randoms(N):
    return ''.join(random.choice("0123456789abcdef") for _ in range(N))

def bruteforce_hexadecimal_4_chars():
    hex_chars = "0123456789ABCDEF"
    for combo in itertools.product(hex_chars, repeat=4):
        password = ''.join(combo)
        yield password

	
def emulate_func(keyc, code):
	#print("Emulate code")  
	try:
	    mu = Uc(UC_ARCH_X86, UC_MODE_16)	
	    # map 2MB memory for this emulation
	    mu.mem_map(ADDRESS, 100 * 1024 * 1024)

	    # write machine code to be emulated to memory
	    mu.mem_write(ADDRESS, code)

	    key = bytes.fromhex(keyc)
	    rkey = make_key2(keyc)

	    keyraw = bytes.fromhex(rkey)#"06010d020e060e01040a070501020304")
	    #keyraw = bytes.fromhex("06010d020e060e01040a070501020304")
	    mu.mem_write(0x2a4c, keyraw)
	    mu.mem_write(DATA_ADDR, key+key)
	    mu.reg_write(UC_X86_REG_EDI, DATA_ADDR)

	    mu.emu_start(0x1296, 0x130B)

	    r_eax = mu.reg_read(UC_X86_REG_EAX)
	    r_edi = mu.reg_read(UC_X86_REG_EDI)

	    if (r_eax == 0):
	    	return True
	    if (r_eax == 0x18E3):
	    	print("Invalid key")
	    	return False
	    elif (r_eax == 0x18FB):
	    	#print("Incorrect key")
	    	return False
	    else:
	    	return True

	except UcError as e:
	    print("ERROR: %s" % e)
	return False

code = None
with open("mem_x1000.bin", "rb") as f:
    code = f.read()
    print("Code read!")
if code is None:
    print("Could not read!");
    exit(-1)
# Initialize emulator in X86-16bit mode
keyc = ""
for chunk in bruteforce_hexadecimal_4_chars():
	#print(chunk)
	keyc = "61d2e6e14a75"+chunk
	if (emulate_func(keyc, code)):
		print("Key=")
		print(keyc)
		break
print("Finished.")
