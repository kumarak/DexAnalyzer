
import sys
from struct import pack, unpack
from core import bytecode

VALUE_BYTE 	=	0x00
VALUE_SHORT	=	0x02
VALUE_CHAR	=	0x03
VALUE_INT	=	0x04
VALUE_LONG	= 	0x06
VALUE_FLOAT	=	0x10
VALUE_DOUBLE =	0x11
VALUE_STRING =	0x17
VALUE_TYPE 	= 	0x18
VALUE_FIELD =	0x19
VALUE_METHOD =	0x1a
VALUE_ENUM	=	0x1b
VALUE_ARRAY	=	0x1c
VALUE_ANNOTATION =	0x1d
VALUE_NULL	=	0x1e
VALUE_BOOLEAN =	0x1f


class DexObject(object):
	"""
	"""
	def __init__(self, buff, cm):
		self.__CM = cm
		self.offset = buff.get_idx()

class EncodedField(object):
	"""
	"""
	def __init__(self, buff, cm):
		self.__CM = cm 
		self.offset = buff.get_idx()

		self.field_idx_diff = bytecode.readuleb128(buff)
		self.access_flags = bytecode.readuleb128(buff)
		self.field_idx = 0

		self.name = None
		self.proto = None
		self.class_name = None

		self.init_value = None
		self.access_flags_string = None

	def reload(self):
		name = self.__CM.get_field(self.field_idx)
		self.class_name = name[0]
		self.name = name[2]
		self.proto = ''.join(i for i in name[1])

	def set_init_value(self, value):
		self.init_value = value

	def get_init_value(self):
		return self.init_value

	def get_field_idx(self):
		return self.field_idx

	def adjust_idx(self, val):
		self.field_idx = self.field_idx_diff + val

class EncodedMethod(object):
	"""
	"""
	def __init__(self, buff, cm):
		self.__CM = cm
		self.offset = buff.get_idx()

		self.method_idx_diff = bytecode.readuleb128(buff)
		self.access_flags = bytecode.readuleb128(buff)
		self.code_off = bytecode.readuleb128(buff)

		self.method_idx = 0
		self.name = None
		self.proto = None
		self.class_name = None
		self.code = None
		self.access_flags_string = None
		self.notes = []

	def adjust_idx(self, val):
		self.method_idx = self.method_idx_diff + val

	def get_method_idx(self):
		return self.method_idx

	def get_method_idx_diff(self):
		return self.method_idx_diff

	def get_access_flags(self):
		return self.access_flags

	def get_code_off(self):
		return self.code_off

	def reload(self):
		pass

class AnnotationElement(object):
	"""
	"""
	def __init__(self, buff, cm):
		self.__CM = cm
		self.offset = buff.get_idx()

		#self.name_idx = bytecode.readuleb128(buff)

class EncodedAnnotation(object):
	"""
	"""
	def __init__(self, buff, cm):
		self.__CM = cm
		self.offset = buff.get_idx()

		self.type_idx = bytecode.readuleb128(buff)
		self.size = bytecode.readuleb128(buff)

		self.elements = []
		for i in xrange(0, self.size):
			self.elements.append(AnnotationElement(buff, cm))

	def show(self):
		bytecode._PrintSubBanner("Encoded Annotation")
		bytecode._PrintDefault("type_idx=%d size=%d\n" % (self.type_idx, self.size))

		for i in self.elements:
			i.show()

	def get_obj(self):
		return [i for i in self.elements]

	def get_raw(self):
		return bytecode.writeuleb128(self.type_idx) + bytecode.writeuleb128(self.size) + ''.join(i.get_raw() for i in self.elements)

	def get_length(self):
		length = len(bytecode.writeuleb128(self.type_idx) + bytecode.writeuleb128(self.size))

		for i in self.elements:
			length += i.get_length()

		return length

class StringDataItem(object):
	"""
		This class can parse a string_data_item of a dex file.
	"""
	def __init__(self, buff, cm):
		self.__CM = cm


class DebugInfoItemEmpty(object):
	"""
	"""
	def __init__(self, buff, cm):
		self.__CM = cm
		self.offset = buff.get_idx()
		self.__buff = buff
		self.__raw 	= ""

	def set_off(self, off):
		self.offset = off

	def get_off(self):
		return self.offset

	def reload(self):
		offset = self.offset
		
		n = self.__CM.get_next_offset_item(offset)
		s_idx = self.__buff.get_idx()
		self.__buff.set_idx(offset)
		self.__raw = self.__buff.read(n - offset)
		self.__buff.set_idx(s_idx)

	def show(self):
		pass

	def get_obj(self):
		return []

	def get_raw(self):
		return self.__raw

	def get_length(self):
		return len(self.__raw)

class EncodedValue(object):
	"""
	"""
	def __init__(self, buff, cm):
		self.__CM = cm
		self.offset = buff.get_idx()

		self.val = unpack("=B", buff.read(1))[0]
		self.value_arg = self.val >> 5
		self.value_type = self.val & 0x1f

		self.raw_value = None
		self.value = ""

		if self.value_type >= VALUE_SHORT and self.value_type < VALUE_STRING:
			self.value, self.raw_value = self._getintvalue(buff.read(self.value_arg + 1))

		elif self.value_type == VALUE_STRING:
			id, self.raw_value = self._getintvalue(buff.read(self.value_arg + 1))
			self.value = cm.get_raw_string(id)

		elif self.value_type == VALUE_TYPE:
			id, self.raw_value = self._getintvalue(buff.read(self.value_arg + 1))
			self.value = cm.get_type(id)

		elif self.value_type == VALUE_FIELD:
			id, self.raw_value = self._getintvalue(buff.read(self.value_arg + 1))
			self.value = cm.get_field(id)

		elif self.value_type == VALUE_METHOD:
			id, self.raw_value = self._getintvalue(buff.read(self.value_arg + 1))
			self.value = cm.get_field(id)

		elif self.value_type == VALUE_ENUM:
			id, self.raw_value = self._getintvalue(buff.read(self.value_arg + 1))
			self.value = cm.get_field(id)

		elif self.value_type == VALUE_ARRAY:
			self.value = EncodedArray(buff, cm) 

		elif self.value_type == VALUE_ANNOTATION:
			self.value = EncodedAnnotation(buff, cm)

		elif self.value_type == VALUE_BYTE:
			self.value = buff.read(1)
		elif self.value_type == VALUE_NULL:
			self.value = None
		elif self.value_type == VALUE_BOOLEAN:
			if self.value_arg:
				self.value = True
			else:
				self.value = False
		else:
			bytecode.Exit("Unknown value 0x%x" % self.value_type)

	def get_value(self):
		return self.value

	def get_value_type(self):
		return self.value_type

	def get_value_arg(self):
		return self.value_arg

	def _getintvalue(self, buf):
		ret = 0
		shift = 0
		for b in buf:
			ret |= ord(b) << shift
			shift += 8

		return ret, buf

	def show(self):
		bytecode._PrintSubBanner("Encoded Value")
		bytecode._PrintDefault("val=%x, value_arg=%x, value_type=%x\n" % (self.val, self.value_arg, self.value_type))

	def get_obj(self):
		if isinstance(self.value, str) == False:
			return [self.value]
		return []

	def get_raw(self):
		if self.raw_value == None:
			return pack("=B", self.val) + bytecode.object_to_str(self.value)
		else:
			return pack("=B", self.val) + bytecode.object_to_str(self.value)

	def get_length(self):
		if self.raw_value == None:
			return len(pack("=B", self.val)) + len(bytecode.object_to_str(self.value))
		else:
			return len(pack("=B", self.val)) + len(bytecode.object_to_str(self.value))

class EncodedArray(object):
	"""
	"""
	def __init__(self, buff, cm):
		self.__CM = cm
		self.offset = buff.get_idx()
		self.size = bytecode.readuleb128(buff)

		self.values = []
		for i in xrange(0, self.size):
			self.values.append(EncodedValue(buff, cm))

	def get_size(self):
		return self.size

	def get_values(self):
		return self.values

	def show(self):
		bytecode._PrintSubBanner("Encoded Array")
		bytecode._PrintDefault("size=%d\n" % self.size)

		for i in self.values:
			i.show()

	def get_obj(self):
		return bytecode.writeuleb128(self.size)

	def get_raw(self):
		return self.get_obj() + ''.join(i.get_raw() for i in self.values)

	def get_length(self):
		length = len(self.get_obj())
		for i in self.values:
			length += i.get_length()

		return length

class EncodedArrayItem(object):
	"""
	"""
	def __init__(self, buff, cm):
		self.__CM = cm
		self.offset = buff.get_idx()
		self.value = EncodedArray(buff, cm)

	def get_off(self):
		return self.offset

	def reload(self):
		pass

	def show(self):
		pass

class ClassDataItem(object):
	"""
	"""
	def __init__(self, buff, cm):
		self.__CM = cm
		self.offset = buff.get_idx()

		print "init class data item"
		self.static_fields_size = bytecode.readuleb128(buff)
		print "static field size ", self.static_fields_size

		self.instance_fields_size = bytecode.readuleb128(buff)
		print "instace_fields_size : ", self.instance_fields_size

		self.direct_methods_size = bytecode.readuleb128(buff)
		print "direct methods size : ", self.direct_methods_size

		self.virtual_methods_size = bytecode.readuleb128(buff)

		print "end class data item"

		self.static_fields = []
		self.instance_fields = []
		self.direct_methods = []
		self.virtual_methods = []

		self._load_elements(self.static_fields_size, self.static_fields, EncodedField, buff, cm)
		self._load_elements(self.instance_fields_size, self.instance_fields, EncodedField, buff, cm)
		self._load_elements(self.direct_methods_size, self.direct_methods, EncodedMethod, buff, cm)
		self._load_elements(self.virtual_methods_size, self.virtual_methods, EncodedMethod, buff, cm)

	def _load_elements(self, size, l, Type, buff, cm):
		prev = 0
		print "load_element : ", size
		for i in xrange(0, size):
			el = Type(buff, cm)
			el.adjust_idx(prev)

			if isinstance(el, EncodedField):
				prev = el.get_field_idx()
			else:
				prev = el.get_method_idx()

			l.append(el)

	def get_off(self):
		return self.offset


	def reload(self):
		for i in self.static_fields:
			i.reload()

		for i in self.instance_fields:
			i.reload()

		for i in self.direct_methods:
			i.reload()

		for i in self.virtual_methods:
			i.reload()

	def show(self):
		pass


class AnnotationItem(object):
	def __init__(self, buff, cm):
		self.__CM = cm
		self.offset = buff.get_idx()

		self.visibility = unpack("=B", buff.read(1))[0]
		self.annotation = EncodedAnnotation(buff, cm)

	def get_off(self):
		return self.offset

	def reload(self):
		pass

	def show(self):
		pass

class AnnotationOffItem(object):
	def __init__(self, buff, cm):
		pass

	def show(self):
		pass


class AnnotationSetItem(object):
	"""
	"""
	def __init__(self, buff, cm):
		self.__CM = cm
		self.offset = buff.get_idx()
		self.annotation_off_item = []
		print "offset : ", self.offset

		self.size = unpack("=I", buff.read(4))[0]
		for i in xrange(0, self.size):
			self.annotation_off_item.append(AnnotationOffItem(buff, cm))
		
	def get_annotation_off_item(self):
		return self.annotation_off_item

	def get_off(self):
		return self.offset

	def set_off(self, off):
		self.offset = off

	def reload(self):
		pass

	def show(self):
		bytecode._PrintSubBanner("Annotation Set Item")
		for i in self.annotation_off_item:
			i.show()

class AnnotationsDirectoryItem(object):
	"""
	"""
	def __init__(self, buff, cm):
		self.__CM = cm
		self.offset = buff.get_idx()

		self.class_annotations_off = unpack("=I", buff.read(4))[0]
		self.annotated_fields_size = unpack("=I", buff.read(4))[0]
		self.annotated_methods_size = unpack("=I", buff.read(4))[0]
		self.annotated_parameters_size = unpack("=I", buff.read(4))[0]

		self.field_annotations = []
		for i in xrange(0, self.annotated_fields_size):
			self.field_annotations.append(FieldAnnotation(buff, cm))

		self.method_annotations = []
		for i in xrange(0, self.annotated_methods_size):
			self.method_annotations.append(MethodAnnotation(buff, cm))

		self.parameter_annotations = []
		for i in xrange(0, self.annotated_parameters_size):
			self.parameter_annotations.append(ParameterAnnotation(buff, cm))

	def get_class_annotation_off(self):
		return self.class_annotations_off

	def get_annotated_fields_size(self):
		return self.annotated_fields_size

	def get_annotated_methods_size(self):
		return self.annotated_methods_size

	def get_annotated_parameters_size(self):
		return self.annotated_parameters_size

	def get_method_annotations(self):
		return self.method_annotations

	def get_field_annotations(self):
		return self.field_annotations

	def get_parameter_annotations(self):
		return self.parameter_annotations

	def get_off(self):
		return self.offset

	def set_off(self, offset):
		self.offset = offset

	def reload(self):
		pass


	def get_off(self):
		return self.offset

	def show(self):
		pass