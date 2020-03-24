#!/usr/bin/python

import os
import sys

if os.getuid():
   print "Please run as root."
   sys.exit(1)

setup_dir = '/opt/gluu/setup'

if not os.path.exists(setup_dir):
   print setup_dir, "does not exist"

sys.path.append(setup_dir)

import gluu_installer

