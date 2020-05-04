#!/usr/bin/env python

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
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

"""
customize.py: Topology for authentication tests

             +---------+
             |    r1   |
             | 1.1.1.1 |
             +----+----+
                  | .1  r1-eth0
                  | 2001:db8:beef:1::1
            ~~~~~~~~~~~~~
          ~~     sw0     ~~                  BGP Only
          ~~ 10.0.1.0/24 ~~
            ~~~~~~~~~~~~~
                  |10.0.1.0/24
                  |2001:db8:beef:1::2
                  | .2  r2-eth0
             +----+----+
             |    r2   |
             | 2.2.2.2 |
             +--+---+--+
    r2-eth2  .2 |
         ______/
        /
  ~~~~~~~~~~~~~
~~     sw2     ~~                            OSPF Only
~~ 10.0.3.0/24 ~~
  ~~~~~~~~~~~~~
        |
         \
          \
r3-eth1 .3 |
      +----+--+---+
      |     r3    |
      |  3.3.3.3  |
      +-----------+
            |r3-eth2 8.0.0.1/8


"""

import os
import re
import pytest
import platform

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.ltemplate import ltemplateRtrCmd

# Required to instantiate the topology builder class.
from mininet.topo import Topo

import shutil
CWD = os.path.dirname(os.path.realpath(__file__))
# test name based on directory
TEST = os.path.basename(CWD)

class ThisTestTopo(Topo):
    "Test topology builder"
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # This function only purpose is to define allocation and relationship
        # between routers, switches and hosts.
        #
        # Create routers
        for routern in range(1, 4):
            tgen.add_router('r{}'.format(routern))
        mach = platform.machine()
        krel = platform.release()
        if mach[:1] == 'a' and topotest.version_cmp(krel, '4.11') < 0:
            logger.info('Need Kernel version 4.11 to run on arm processor')
            return

        #CE/PE links

        # Create a switch with just one router connected to it to simulate a
        # empty network.
        switch = {}
        switch[0] = tgen.add_switch('sw0')
        switch[0].add_link(tgen.gears['r1'], nodeif='r1-eth0')
        switch[0].add_link(tgen.gears['r2'], nodeif='r2-eth0')

        switch[1] = tgen.add_switch('sw2')
        switch[1].add_link(tgen.gears['r2'], nodeif='r2-eth2')
        switch[1].add_link(tgen.gears['r3'], nodeif='r3-eth1')
        switch[1].add_link(tgen.gears['r3'], nodeif='r3-eth2')

l3mdev_accept = 0

def ltemplatePreRouterStartHook():
    global l3mdev_accept
    cc = ltemplateRtrCmd()
    krel = platform.release()
    tgen = get_topogen()
    logger.info('pre router-start hook, kernel=' + krel)
    #check for normal init
    if len(tgen.net) == 1:
        logger.info('Topology not configured, skipping setup')
        return False
    #trace errors/unexpected output
    cc.resetCounts()
    return True

def ltemplatePostRouterStartHook():
    logger.info('post router-start hook')
    return True
