

from autoconf import CONF

import hashlib


class SV(object):
	def __init__(self, size, buff):
		self.__size = size
		self.__value = unpack(self.__size, buff)[0]

	def _get(self):
		return pack(self.__size, self.__value)

	def __str__(self):
		return "0x%x" % self.__value

	def __int__(self):
		return self.__value

	def get_value_buff(self):
		return self._get()

	def get_value(self):
		return self.__value

	def set_value(self, attr):
		self.__value = attr


class _Bytecode(object):
	def __init__(self, buff):
		print "init Bytecode"
		try:
			import psyco
			psyco.full()
		except ImportError:
			print "Import Error inside Bytecode"
			pass

		self.__buff = buff
		self.__idx = 0

	def read(self, size):
		if isinstance(size, SV):
			size = size.value

		buff = self.__buff[self.__idx : self.__idx + size]
		self.__idx += size

		return buff

	def readat(self, off):
		if isinstance(off, SV):
			off = off.value

		return self.__buff[off : ]

	def read_b(self, size):
		return self.__buff[self.__idx : self.__idx + size ]

	def set_idx(self, idx):
		self.__idx = idx

	def get_idx(self):
		return self.__idx

	def add_idx(self, idx):
		self.__idx += idx


def Exit(msg):
	warning("Error : " + msg)
	raise("oops")

def Warning(msg):
	pass
	#warning(msg)

def _PrintBanner():
	print_fct = CONF["PRINT_FCT"]
	print_fct("*" * 75 + "\n")

def _PrintSubBanner(title=None):
	print_fct = CONF["PRINT_FCT"]
	if title == None:
		print_fct("#" * 20 + "\n")
	else:
		print_fct("#" * 10 + title + "\n")

def _PrintNote(note, tab=0):
	pass

def _PrintDefault(msg):
	print_fct = CONF["PRINT_FCT"]
	print_fct(msg)