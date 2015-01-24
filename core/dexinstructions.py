

class Instruction(object):
	def get_kind(self):
		if self.OP > 0xff:
			if self.OP >= 0xf2ff:
				return DALVIK_OPCODES_OPTIMIZED[self.OP][1][1]
			return DALVIK_OPCODES_EXTENDED_WIDTH[self.OP][1][1]
		return DALVIK_OPCODES_FORMAT[self.OP][1][1]

	def get_name(self):
		if self.OP > 0xff:
			if self.OP >= 0xf2ff:
				return DALVIK_OPCODES_OPTIMIZED[self.OP][1][0]
			return DALVIK_OPCODES_EXTENDED_WIDTH[self.OP][1][0]
		return DALVIK_OPCODES_FORMAT[self.OP][1][0]

	def get_output(self, idx=-1):
		return "not implemented"
		#raise("not implemented")


	def show(self, idx):
		print self.get_name() + " " + self.get_output(idx)

class Instruction10x(Instruction):
	"""
	"""
	def __init__(self, cm, buff):
		pass


class Instruction12x(Instruction):
	"""
	"""
	def __init__(self, cm, buff):
		pass


class Instruction22x(Instruction):
	"""
	"""
	def __init__(self, cm, buff):
		pass


class Instruction32x(Instruction):
	"""
	"""
	def __init__(self, cm, buff):
		pass



class Unresolved(Instruction):
	def __init__(self, cm, data):
		self.cm = cm
		self.data = data

	def get_name(self):
		return "unresolved"

	def get_output(self, idx=-1):
		return repr(self.data)

	def get_length(self):
		return len(self.data)

	def get_raw(self):
		return self.data