#!/usr/bin/env python
from capstone import *

#types of conditional jumps
condit_str = {'jo', 'jno', 'js', 'jns', 'je', 'jx', 'jne', 'jnz', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jbe', 'jna', 'ja', 'jnbe', 'jl', 'jnge', 'jge', 'jnl', 'jle', 'jng', 'jg', 'jnle', 'jp', 'jpe', 'jnp', 'jpo', 'jcxz', 'jecxz', 'loop'}
#types of unconditional jumps
uncond_str = {'jmp', 'call'}
#return has a special result


shellcode = ""

with open('hello', 'r') as myfile:
	shellcode =myfile.read()#.replace('\n', '')
md = Cs(CS_ARCH_X86, CS_MODE_32)
elfcheck = True
firstmagic = False
secondmagic = False
iself = False
for i in md.disasm(shellcode, 0x00):
	if iself == False:
		if (i.address == 0x00) and (i.mnemonic == 'jg') and (i.op_str == '0x47') :
			firstmagic = True
		if (i.address == 0x02) and (i.mnemonic == 'dec') and (i.op_str == 'esp') :
			secondmagic = True
		if firstmagic and secondmagic :
			print("This is an ELF file")
			iself = True
	else:
		print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
	#if i.mnemonic in condit_str:
	#	print("")#print("Conditional Jump!")
	#if i.mnemonic in uncond_str:
	#	print("")#print("Unconditional Jump!")
	#if i.mnemonic == "return":
	#	print("")#print("Return!")