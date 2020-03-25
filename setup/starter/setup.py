#!/usr/bin/python3

import os
import sys
import site

if os.getuid():
    print("Please run as root.")
    sys.exit(1)

setup_base_dir = '/opt/install'

if not os.path.exists(setup_base_dir):
    print(setup_base_dir, "does not exist")
    sys.exit(1)

site.addsitedir(setup_base_dir)

from community_edition_setup import setup

setup.begin_setup()
