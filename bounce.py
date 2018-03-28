#!/usr/bin/env python
from capstone import *
import argparse, re, subprocess

#types of conditional jumps
condit_str = {'jo', 'jno', 'js', 'jns', 'je', 'jx', 'jne', 'jnz', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jbe', 'jna', 'ja', 'jnbe', 'jl', 'jnge', 'jge', 'jnl', 'jle', 'jng', 'jg', 'jnle', 'jp', 'jpe', 'jnp', 'jpo', 'jcxz', 'jecxz', 'loop'}
#types of unconditional jumps
uncond_str = {'jmp', 'call'}
#return has a special result

recursive_list = ["0x00"] #We start with only the base value to parse
pairs_list = []
timothy = ""
first = 0
last = 0
md = Cs(CS_ARCH_X86, CS_MODE_32)

def linear_disasm(binary, start = 0x00):
	for oper in md.disasm(binary, start):
		print("0x%x:\t%s\t%s" %(oper.address, oper.mnemonic, oper.op_str))

def unchecked( address ):
	print("Base: %s"%address)
	for p in pairs_list :
		print("Compare: %s %s"%(int(p[0]), int(p[1])))
		if (address >= p[0]) and (address < p[1]) :
			return False
	print("Haven't gone there!")
	return True	
	
def addpoints ( first, last ):
	newpoint = [first, last]
	pairs_list.append(newpoint)

'''
def recursive_disasm(start, file, i):
	f = open(file, 'rb')	
	while i < len(timothy):
		bill = timothy[i]
		print("0x%x:\t%s\t%s" %(bill.address, bill.mnemonic, bill.op_str))
		if (bill.mnemonic == 'return'):
			return
		if (bill.mnemonic in uncond_str):
			addpoints(start, bill.address)
			try:			
				ti = int(bill.op_str, 16)
				if unchecked(ti): # If we've already written this part there's no need to do it again.
					print("Going to "+bill.op_str)
					recursive_disasm(start, ti-start)
			except ValueError as e:
				print("Apologies- Non-int jump")
			return		
		if (bill.mnemonic in condit_str):
			addpoints(start, bill.address)
			try:			
				ti = int(bill.op_str, 16)
				if unchecked(ti): # If we've already written this part there's no need to do it again.
					print("Going to "+bill.op_str)
					recursive_disasm(start, ti-start)
			except ValueError as e:
				print("Apologies- Non-int jump")		
		i = i+1
	print("Done!")

'''

def recursive_disasm(start, i):
	while i < len(timothy):
		bill = timothy[i]
		print("0x%x:\t%s\t%s" %(bill.address, bill.mnemonic, bill.op_str))
		if (bill.mnemonic == 'return'):
			return
		if (bill.mnemonic in uncond_str):
			addpoints(start, bill.address)
			try:			
				ti = int(bill.op_str, 16)
				print(bill.op_str+" is "+str(ti-start)+" units away. We are at "+str(i)+" and go as far as "+str(len(timothy)))				
				if unchecked(ti): # If we've already written this part there's no need to do it again.
					recursive_disasm(start, ti-start)
				
			except ValueError as e:
				print("Apologies- Non-int jump")
			return		
		if (bill.mnemonic in condit_str):
			addpoints(start, bill.address)
			try:			
				ti = int(bill.op_str, 16)
				print(bill.op_str+" is "+str(ti-start)+" units away. We are at "+str(i)+" and go as far as "+str(len(timothy)))		
				if unchecked(ti): # If we've already written this part there's no need to do it again.
					recursive_disasm(start, ti-start)
			except ValueError as e:
				print("Apologies- Non-int jump")		
		i = i+1
	print("Done!")

def get_elf_entry_point(file):
	cmd = subprocess.Popen('readelf -h ' + file, shell=True, stdout=subprocess.PIPE)
	address_regex = re.compile("^(?: *)Entry point address:(?: *)(0x[0-9]+)(?: *)$")
	for line in cmd.stdout:
		if "Entry point address:" in line:
			address = address_regex.search(line)
			if address:
				return int(address.group(1), 0)
			else:
				print "ERROR: Tried to find entry point address using readelf -h " + file + ", but could not parse line!"
				exit()
	print "ERROR: Tried to find entry point address using readelf -h " + file + ", but did not find entry point information!"
	exit()


def is_elf(file_disas):
	magic_numbers = [127, 76, 70, 2]
	index = 0

	# Iterate through the first four bytes of the file and compare them to the ELF magic number.
	for op in file_disas:

		# If all of the four magic numbers matched the file, return True
		if index + 1 >= len(magic_numbers):
			return True
		
		# If the current byte doesn't match it's corresponding magic number, return False
		elif op.bytes[0] != magic_numbers[index]:
			return False
		index += 1

	# In the case the file is less then 4 bytes, return False
	return False

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Disassemble a binary or an ELF file using recursive or linear disassembly.')
	parser.add_argument('--file', metavar='f', type=argparse.FileType('rb'), help='the file to disassemble', required=True)
	parser.set_defaults(disas_type='linear')
	
	disassembly_type = parser.add_mutually_exclusive_group()
	disassembly_type.add_argument('--linear', action='store_const', dest='disas_type', const='linear')
	disassembly_type.add_argument('--recursive', action='store_const', dest='disas_type', const='recursive')

	args = parser.parse_args()
	shellcode = args.file.read()

	# First, we disassemble the file to verify whether it is an elf file and where the proper entry point is.
	file_disas = md.disasm(shellcode, 0x00)
	if is_elf(file_disas):
		print "This is an ELF File!."
		entry_point = get_elf_entry_point(args.file.name)
	else:
		print "This is not an ELF File!"
		entry_point = 0x00

	# Once we have identified the entry point, we run the requested disassembler. By default, we use a linear disassembler.
	if args.disas_type == 'linear':
		linear_disasm(shellcode, entry_point)
	elif args.disas_type == 'recursive':
		timothy = list(md.disasm(shellcode, entry_point))
		recursive_disasm(entry_point, 0)
		#print "To be implemented!" #TODO: Implement recursive disassembler.
	else:
		print "ERROR: Unexpected disassembly type that is not implemented in this version!"
