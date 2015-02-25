

from autoconf import CONF

import sys, traceback
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
		self.__buff = buff
		self.__idx = 0

		#print "buff length : ", len(buff)

	def read(self, size):
		if isinstance(size, SV):
			size = size.value

		buff = self.__buff[self.__idx : self.__idx + size]
		self.__idx += size
		#print "current index : ", self.__idx, " : size : ", size
		if size > 20000:
			traceback.print_exc()
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

def readuleb128(buff):
	result = ord(buff.read(1))
	#print "checkpoint 1 : ", result
	if result > 0x7f:
		cur = ord(buff.read(1))
		result = (result & 0x7f) | ((cur & 0x7f) << 7)
		#print "checkpoint 2 : ", result
		if cur > 0x7f:
			cur = ord(buff.read(1))
			result |= (cur & 0x7f) << 14
			#print "checkpoint 3 : ", result
			if cur > 0x7f:
				cur = ord(buff.read(1))
				result |= (cur & 0x7f) << 21
				#print "checkpoint 4 : ", result
				if cur > 0x7f:
					cur = ord(buff.read(1))
					if cur > 0x0f:
						warning("passible error while decoding")
					result |= cur << 28
					#print "checkpoint 5 : ", result

	#print "checkpoint 6 : ", result
	return result

def utf8_to_string(buff, length):
	chars = []

	for i in xrange(length):
		first_char = ord(buff.read(1))
		value = first_char >> 4
		if value in (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07):
			if first_char == 0:
				warning("at offset %x: single zero byte illegal" % (buff.get_idx()))

			chars.append(chr(first_char))
		elif value in (0x0c, 0x0d):
			second_char = ord(buff.read(1))
			if (second_char & 0xc0) != 0x80:
				warning("bad utf8 at offset: %x" % buff.get_idx())
			value = ((first_char & 0x1f) << 6) | (second_char & 0x3f)
			if value != 0 and value < 0x80:
				warning("at offset %x:" % buff.get_idx())
			chars.append(unichr(value))
		elif value == 0x0e:
			second_char = ord(buff.read(1))
			if second_char & 0xc0 != 0x80:
				warning('bad utf8 byte %x at offset %x' % (second_char, buff.get_idx()))

			third_char = ord(buff.read(1))
			if third_char & 0xc0 != 0x80:
				warning('bad utf8 byte %x at offset %x' % (third_char, buff.get_idx()))
			
			value = ((first_char & 0x0f) << 12) | ((second_char & 0x3f) << 6) | (third_char & 0x3f)
			if value < 0x800:
				warning('at offset %x: utf8 should have been represented with two-byte encoding' % buff.get_idx())

			chars.append(unichr(value))
		else:
			warning('at offset %x: illegal utf8' % buff.get_idx())

	return ''.join(chars).encode('utf-8')
