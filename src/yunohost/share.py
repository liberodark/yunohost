# -*- coding: utf-8 -*-

""" License
    Copyright (C) 2013 YunoHost
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses
"""

""" yunohost_share.py
    Manage share rules
"""
import os
import sys
import yaml
try:
    import miniupnpc
except ImportError:
    sys.stderr.write('Error: Yunohost CLI Require miniupnpc lib\n')
    sys.exit(1)

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils import process
from moulinette.utils.log import getActionLogger
from moulinette.utils.text import prependlines

SHARE_FILE = '/etc/yunohost/share.yml'
