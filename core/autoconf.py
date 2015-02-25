
import sys
import os
import logging

class Color(object):
	Normal = "\033[0m"
	Black = "\033[30m"
	Red = "\033[31m"
	Green = "\033[32m"
	Yellow = "\033[33m"
	Blue = "\033[34m"
	Purple = "\033[35m"
	Cyan = "\033[36m"
	Grey = "\033[37m"
	Bold = "\033[1m"

CONF = {
	"BIN_DED": "ded.sh",

	"RECODE_ASCII_STRING": False,
	"RECODE_ASCII_STRING_METH": None,

	"COLORS": {
		"OFFSET": Color.Yellow,
		"OFFSET_ADDR": Color.Green,
		"INSTRUCTION_NAME": Color.Yellow,
	},

	"PRINT_FCT": sys.stdout.write,
	"LAZY_ANALYSIS": False,
	"MAGIC_PATH_FILE": None,
}


log_runtime = logging.getLogger("dexanalyzer.runtime")

def default_colors(obj):
	CONF["COLORS"]["OFFSET"] = obj.Yellow
	CONF["COLORS"]["OFFSET_ADDR"] = obj.Green
	CONF["COLORS"]["INSTRUCTION_NAME"] = obj.Yellow

def is_ascii_problem(s):
	try:
		s.decode("ascii")
		return False
	except UnicodeDecodeError:
		return True

def error(x):
	log_runtime.error(x)
	raise()

def debug(x):
	log_runtime.debug(x)

def is_android_raw(buff):
	val = None
	f_bytes = buff[:7]

	if f_bytes[0:2] == "PK":
		val = "APK"
	elif f_bytes[0:3] == "dex":
		val = "DEX"
	elif f_bytes[0:3] == "dey":
		val = "DEY"
	elif f_bytes[0:7] == "\x7fELF\x01\x01\x01":
		val = "ELF"

	return val


def is_android(filename):
	if not filename:
		return None

	val = None
	with open(filename, "r") as fd:
		f_bytes = fd.read(7)
		val = is_android_raw(f_bytes)

	return val