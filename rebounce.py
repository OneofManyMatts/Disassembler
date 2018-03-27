#!/usr/bin/env python
from capstone import *

#types of conditional jumps
condit_str = {'jo', 'jno', 'js', 'jns', 'je', 'jx', 'jne', 'jnz', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jbe', 'jna', 'ja', 'jnbe', 'jl', 'jnge', 'jge', 'jnl', 'jle', 'jng', 'jg', 'jnle', 'jp', 'jpe', 'jnp', 'jpo', 'jcxz', 'jecxz', 'loop'}
#types of unconditional jumps
uncond_str = {'jmp', 'call'}
#return has a special result


recursive_list = ["0x00"] #We start with only the base value to parse
pairs_list = []

def str_to_hex( strin ):
	return int(strin, 0)

def unchecked( address ):
	#print("Base: %s"%(int(address, 0)))
	for p in pairs_list :
		#print("Compare: %s %s"%(int(p[0]), int(p[1])))
		if (int(address, 0) >= p[0]) and (int(address, 0) <= p[1]) :
			return False
	return True
	
def addpoints ( first, last ):
	newpoint = [first, last]
	pairs_list.append(newpoint)

def recursive ( start , code ) :
	md = Cs(CS_ARCH_X86, CS_MODE_32)
	for i in md.disasm(code, start):
		print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
		if (i.mnemonic == 'return'):
			break
		if (i.mnemonic in uncond_str):
			addpoints(start, i.address)
			if unchecked(i.op_str): # If we've already written this part there's no need to do it again.
				recursive(str_to_hex(i.op_str), code)
			break
		if (i.mnemonic in condit_str):
			addpoints(start, i.address)
			if unchecked(i.op_str): # If we've already written this part there's no need to do it again.
				recursive(str_to_hex(i.op_str), code)

def checkelf (code):
	firstmagic = False
	secondmagic = False
	check = 0
	my = Cs(CS_ARCH_X86, CS_MODE_32)
	for i in my.disasm(code, 0x00):
		check = check + 1		
		if (i.address == 0x00) and (i.mnemonic == 'jg') and (i.op_str == '0x47') :
			firstmagic = True
		if (i.address == 0x02) and (i.mnemonic == 'dec') and (i.op_str == 'esp') :
			secondmagic = True
		if check > 1:
			if firstmagic and secondmagic :
				print("This is an ELF file")
				return True
			else:
				print("This is not an ELF file")
				return False				

shellcode = ""

with open('hello', 'r') as myfile:
	shellcode = myfile.read()#.replace('\n', '')
md = Cs(CS_ARCH_X86, CS_MODE_32)
start = 0x00
if checkelf( shellcode ):
	start = 0x03
recursive( start , shellcode )