from capstone import *

conditional_jumps = {'jo', 'jno', 'js', 'jns', 'je', 'jx', 'jne', 'jnz', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jbe', 'jna', 'ja', 'jnbe', 'jl', 'jnge', 'jge', 'jnl', 'jle', 'jng', 'jg', 'jnle', 'jp', 'jpe', 'jnp', 'jpo', 'jcxz', 'jecxz', 'loop'}
unconditional_jumps = {'jmp', 'call'}


recursive_list = ["0x00"] #We start with only the base value to parse
pairs_list = []
timothy = ""
first = 0
last = 0

def capstone_disasm(file_name, start, size, arch, linear):
	# Load file into a string buffer
	with open(file_name,'r') as file:
		file_content = file.read()

	if arch == 64:
		md = Cs(CS_ARCH_X86, CS_MODE_64)
	else:
		md = Cs(CS_ARCH_X86, CS_MODE_32)

	if linear:
		print "Running Capstone Linear Disassembler (" + str(arch) + "-bit) starting from " + str(start) + " for " + str(size) + " bytes!"
		for i, oper in enumerate(md.disasm(file_content, start)):
			print("0x%x:\t%s\t%s" % (oper.address, oper.mnemonic, oper.op_str))

			if i > size:
				break
	else:
		recursive_disasm_capstone(start, file, 0x00, md)


def unchecked( address ):
	print("Base: %s"%address)
	for p in pairs_list:
		print("Compare: %s %s"%(int(p[0]), int(p[1])))
		if (address >= p[0]) and (address < p[1]) :
			return False
	#print("Haven't gone there!")
	return True	
	
def update_list():
	for p in pairs_list:
		for g in pairs_list:
			if p == g:
				break
			p_0 = p[0]
			p_1 = p[1]
			g_0 = g[0]
			g_1 = g[1]
			if p_0 == g_0 and p_1 == g_1 :
				pairs_list.remove(g)
				break
			if p_0 <= g_0 and p_1 >= g_1 :
				pairs_list.remove(g)
				break
			if p_0 <= g_0 and p_1 <= g_1 :
				pairs_list.remove(p)
				pairs_list.remove(g)
				addpoints(p_0, g_1)
				break
			if g_0 <= p_0 and g_1 >= p_1 :
				pairs_list.remove(p)
				break
			if g_0 <= p_0 and g_1 <= p_1 :
				pairs_list.remove(p)
				pairs_list.remove(g)
				addpoints(g_0, p_1)				

def addpoints ( first, last ):
	newpoint = [first, last]
	print("Adding: %s %s"%(first, last))
	pairs_list.append(newpoint)
	update_list()

def recursive_disasm_capstone(start, f, i, md):
	#print("Going to "+str(i))
	try:
		f.seek(i)
	except IOError as e:
		print("Impossible jump")
		return
	j = i
	for line in f:
		bill = None
		for will in md.disasm(line, start):
			bill = will
			print("0x%x:\t%s\t%s" %(bill.address, bill.mnemonic, bill.op_str))
			if bill.mnemonic == 'ret':
				return
			if bill.mnemonic in unconditional_jumps:
				addpoints(start, bill.address+len(bill.bytes))
				try:			
					ti = int(bill.op_str, 0)
					tj = int(start)
					if unchecked(ti): # If we've already written this part there's no need to do it again.
						recursive_disasm_capstone(ti, f, ti-tj+i, md)
				except ValueError as e:
					print("Apologies- Non-int jump")
				return	
			if bill.mnemonic in conditional_jumps:
				addpoints(start, bill.address+len(bill.bytes))
				try:			
					ti = int(bill.op_str, 0)
					tj = int(start)
					if unchecked(ti): # If we've already written this part there's no need to do it again.
						print("Going to "+bill.op_str)
						recursive_disasm_capstone(ti, f, ti-tj+i, md)
				except ValueError as e:
					print("Apologies- Non-int jump!")
