#!/usr/bin/env python

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020, LabN Consulting, L.L.C.
# Authored by Lou Berger <lberger@labn.net>
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

import os
import sys
import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../'))

from lib.ltemplate import *

CliOnFail = None
# For debugging, uncomment the next line
CliOnFail = 'tgen.mininet_cli'

#code currently doesn't handle case where key created after startup
def test_init_keys():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    ltemplateTest('scripts/init-keys.py', False, CliOnFail, CheckFunc)

def test_check_keys1():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    ltemplateTest('scripts/check-keys.py', False, CliOnFail, CheckFunc)

#test conversion first (then do re-boots, and test again)

def test_rip_show1():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    ltemplateTest('scripts/rip-show.py', False, CliOnFail, CheckFunc)

def test_ripng_show1():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    ltemplateTest('scripts/ripng-show.py', False, CliOnFail, CheckFunc)

#test conversion
def test_ospf_neighbors1():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    ltemplateTest('scripts/ospf-neighbors.py', False, CliOnFail, CheckFunc)

def test_bgp_adjacencies1():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    ltemplateTest('scripts/bgp-adjacencies.py', False, CliOnFail, CheckFunc)

def test_notification_check1():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    ltemplateTest('scripts/notification_check.py', False, CliOnFail, CheckFunc)

#do restarts
def test_restart_rip():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    ltemplateTest('scripts/restart-rip.py', False, CliOnFail, CheckFunc)

def test_restart_ospf():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    ltemplateTest('scripts/restart-ospf.py', False, CliOnFail, CheckFunc)

def test_restart_bgp():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    ltemplateTest('scripts/restart-bgp.py', False, CliOnFail, CheckFunc)

def test_check_keys2():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    ltemplateTest('scripts/check-keys.py', False, CliOnFail, CheckFunc)

#test load from file
def test_rip_show2():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    ltemplateTest('scripts/rip-show.py', False, CliOnFail, CheckFunc)

def test_ospf_neighbors2():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    ltemplateTest('scripts/ospf-neighbors.py', False, CliOnFail, CheckFunc)

def test_bgp_adjacencies2():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    ltemplateTest('scripts/bgp-adjacencies.py', False, CliOnFail, CheckFunc)

def test_notification_check():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    ltemplateTest('scripts/notification_check.py', False, CliOnFail, CheckFunc)

if __name__ == '__main__':
    retval = pytest.main(["-s"])
    sys.exit(retval)
