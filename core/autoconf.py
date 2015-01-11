
import sys
import os
import logging

CONF = {
	"BIN_DED": "ded.sh",

	"RECODE_ASCII_STRING": False,
	"RECODE_ASCII_STRING_METH": None,

	"PRINT_FCT": sys.stdout.write,
	"LAZY_ANALYSIS": False,
	"MAGIC_PATH_FILE": None,
	}


log_runtime = logging.getLogger("dexanalyzer.runtime")

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