#!/usr/bin/python

import sys

from core.bytecodes import dvm
from core.util import read

TEST_CASE = "/home/akshayk/Downloads/android_apk/classes.dex"

j = dvm.DalvikVMFormat(read(TEST_CASE, binary=False))

j.show()
