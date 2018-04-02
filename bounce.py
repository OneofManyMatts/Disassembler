#!/usr/bin/env python
from capstone import *
from disas_capstone import *
from disas_pydasm import *
import argparse, re, subprocess, sys, math

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

# This finds the start point of the file in memory.
def get_elf_base_point(file_name):
	cmd = subprocess.Popen('readelf -l ' + file_name, shell=True, stdout=subprocess.PIPE)
	address_regex = re.compile("^(?: +)LOAD(?: +)0x(?:[0-9]+) 0x([0-9]+)")
	for line in cmd.stdout:
		if "LOAD" in line:
			address = address_regex.search(line)
			if address:
				return int(address.group(1).lstrip("0"), 0)
			else:
				print "ERROR: Tried to find base address using readelf -l " + file_name + ", but could not parse line!"
				exit()
	print "ERROR: Tried to find base address using readelf -l " + file_name + ", but did not find LOAD section information!"
	exit()

# This finds the entry point of the program then returns that value - the start of the file.
def get_elf_entry_point(file_name):
	cmd = subprocess.Popen('readelf -h ' + file_name, shell=True, stdout=subprocess.PIPE)
	address_regex = re.compile("^(?: *)Entry point address:(?: *)0x([0-9a-f]+)(?: *)$")
	for line in cmd.stdout:
		if "Entry point address:" in line:
			address = address_regex.search(line)
			if address:
				return int(address.group(1), 0) - get_elf_base_point(file_name)
			else:
				print "ERROR: Tried to find entry point address using readelf -h " + file_name + ", but could not parse line!"
				exit()
	print "ERROR: Tried to find entry point address using readelf -h " + file_name + ", but did not find entry point information!"
	exit()

# This parses a given line of readelf -S <file> for the section size.
def parse_section_size(section_line, section_name, file_name):
	size_regex = re.compile("^(?:.+)(?:" + section_name + ")(?: +)(?:\w+)(?: +)(?:\w+)(?: +)(?:\w+)(?: +)(\w+)(?: )+")
	size = size_regex.search(section_line)
	if size:
		return int(size.group(1).strip("0"), 0)
	else:
		print section_line
		print "ERROR: Tried to find " + section_name + " section size using readelf -S " + file_name + ", but could not parse line!"
		exit()

# This parses readelf -S <file> for the .text section and then returns parse_section_size() on that line.
def get_text_section_size(file_name):
	cmd = subprocess.Popen('readelf -S ' + file_name, shell=True, stdout=subprocess.PIPE)

	text_section_line = "" # The CMD tends to split the output into multiple lines.
	found_text_section = False

	new_section_regex = re.compile("^(?: +)([[0-9]+])(?: +)(\.\w+)")
	for line in cmd.stdout:
		new_section = new_section_regex.search(line)
		if found_text_section:
			if new_section:
				return parse_section_size(text_section_line, ".text", file_name)
			else:
				text_section_line += line.rstrip()
		elif new_section and ".text" in line:
			text_section_line = line.rstrip()
			found_text_section = True

	print "ERROR: Tried to find .text section size using readelf -S " + file_name + ", but did not find .text section information!"
	exit()

def get_entry_point_and_size(file_name, file_content, arch):
	if arch == 64:
		md = Cs(CS_ARCH_X86, CS_MODE_64)
	else:
		md = Cs(CS_ARCH_X86, CS_MODE_32)

	file_disas = md.disasm(file_content, 0x00)
	if is_elf(file_disas):
		print "This is an ELF File!"
		return (get_elf_entry_point(file_name), get_text_section_size(file_name))
	else:
		print "This is not an ELF File!"
		return (0x00, sys.getsizeof(file_content))

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Disassemble a binary or an ELF file using recursive or linear disassembly.')
	parser.add_argument('--file', metavar='f', type=argparse.FileType('r'), help='the file to disassemble', required=True)
	parser.set_defaults(disas_type='linear', disas_lib='capstone', disas_arch=32)
	
	disassembly_type = parser.add_mutually_exclusive_group()
	disassembly_type.add_argument('--linear', action='store_const', dest='disas_type', const='linear')
	disassembly_type.add_argument('--recursive', action='store_const', dest='disas_type', const='recursive')

	disassembler_lib = parser.add_mutually_exclusive_group()
	disassembler_lib.add_argument('--capstone', action='store_const', dest='disas_lib', const='capstone')
	disassembler_lib.add_argument('--pydasm', action='store_const', dest='disas_lib', const='pydasm')
	# disassembler_lib.add_argument('--pyxed', action='store_const', dest='disas_lib', const='pyxed')

	disassembler_arch = parser.add_mutually_exclusive_group()
	disassembler_arch.add_argument('--64', action='store_const', dest='disas_arch', const=64)
	disassembler_arch.add_argument('--32', action='store_const', dest='disas_arch', const=32)

	args = parser.parse_args()
	file_name = args.file.name
	file_content = args.file.read()
	(entry_point, disas_size) = get_entry_point_and_size(file_name, file_content, args.disas_arch)

	if args.disas_lib == 'capstone':
		capstone_disasm(args.file, entry_point, disas_size, args.disas_arch, (args.disas_type == 'linear'))
	elif args.disas_lib == 'pydasm':
		pydasm_disasm(file_name, entry_point, disas_size, (args.disas_type == 'linear'))
	#elif args.disas_lib == 'pyxed':
	#	pyxed_disasm(file_content, entry_point, disas_size, args.disas_arch, (args.disas_type == 'linear'))
	else:
		print "ERROR: Unexpected disassembly type that is not implemented in this version!"

