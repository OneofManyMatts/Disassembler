import pydasm
from recursive_disas_helper import *

def pydasm_disasm(file_name, start, size, linear):

	if linear:
		print "Running Pydasm Linear Disassembler starting from " + str(start) + " for " + str(size) + " bytes!"

		# Load file into a string buffer
		with open(file_name,'r') as f:
			f.seek(start)
			buffer = f.read(size)

		# Iterate through the buffer and disassemble 
		offset = 0
		while offset < len(buffer):
			i = pydasm.get_instruction(buffer[offset:], pydasm.MODE_32)
			print pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, 0)
			if not i:
				break
			offset += i.length
	else:
		pydasm_disasm_recursive(file_name, start, start + size, start, [])
		print "Pydasm - RECURSIVE: TO BE IMPLEMENTED!"

def pydasm_disasm_recursive(file_name, loadStart, loadEnd, pos, history):
	with open(file_name,'r') as f:
		f.seek(loadStart + pos)
		buffer = f.read(loadEnd-pos)

	# Iterate through the buffer and disassemble 
	offset = 0
	while offset < len(buffer):
		if (pos + offset) not in history:

			history.append((pos + offset))

			inst = pydasm.get_instruction(buffer[offset:], pydasm.MODE_32)
			if not inst:
				break

			inst_str = pydasm.get_instruction_string(inst, pydasm.FORMAT_INTEL, 0)
			print inst_str

			if is_jump(inst_str):
				jump_loc = pydasm.get_operand_string(inst, 0, pydasm.FORMAT_INTEL, 0)
				try:
					parsed_jump_loc = int(jump_loc, 16)
					if not is_new_jump(int(jump_loc, 16), history):
						print "Did not go to jump because location has already been visited. (" + jump_loc + ")"
					else:
						print "Jumping to " + jump_loc + "!"
						history.append(pydasm_disasm_recursive(file_name, loadStart, loadEnd, parsed_jump_loc, history))
						print "Returned from jumping to " + jump_loc + "!"
				except ValueError:
					print "Did not go to jump because location is not numeric. (" + jump_loc + ")"

				if is_unconditional_jump(inst_str):
					return history

		offset += inst.length

	return history