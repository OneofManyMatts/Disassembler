all_jump = ['jo', 'jno', 'js', 'jns', 'je', 'jx', 'jne', 'jnz', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jbe', 'jna', 'ja', 'jnbe', 'jl', 'jnge', 'jge', 'jnl', 'jle', 'jng', 'jg', 'jnle', 'jp', 'jpe', 'jnp', 'jpo', 'jcxz', 'jecxz', 'loop', 'jmp', 'call']
conditional_jumps = ['jo', 'jno', 'js', 'jns', 'je', 'jx', 'jne', 'jnz', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jbe', 'jna', 'ja', 'jnbe', 'jl', 'jnge', 'jge', 'jnl', 'jle', 'jng', 'jg', 'jnle', 'jp', 'jpe', 'jnp', 'jpo', 'jcxz', 'jecxz', 'loop']
unconditional_jumps = ['jmp', 'call']

def is_jump(test_inst):
	return (len([inst for inst in all_jump if inst in test_inst]) > 0)

def is_conditional_jump(test_inst):
	return (len([inst for inst in conditional_jumps if inst in test_inst]) > 0)

def is_unconditional_jump(test_inst):
	return (len([inst for inst in unconditional_jumps if inst in test_inst]) > 0)

def visited(location, history):
	for (start, end) in history:
		if location >= start and location <= end:
			return True
	return False

def valid_jump(loc, start, end):
	return (loc >= start) and (loc <= end)

def is_new_jump(loc, history):
	return loc not in history