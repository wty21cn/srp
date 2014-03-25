# coding:utf-8
#
# Copyright 2014 Rain Wang
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pox.core import core
from pox.lib.revent import EventMixin,Event
from collections import namedtuple
from pox.lib.util import dpid_to_str,str_to_bool
from pox.lib.revent import EventHalt
from pox.lib.recoco import Timer
from pox.lib.addresses import parse_cidr,parse_network

import time
import datetime
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt


#Global Var
log = core.getLogger()

class SRPGrid_Row(dict):

    def __init__(self,desc,prefix,mask):
        dict.__init__({})
        self.desc = desc
        self.prefix = prefix
        self.mask  = mask


class SRPGrid(list):

    def __init__(self,dpid):
        list.__init__([])
        self.dpid = dpid

    def __repr__(self):
        repr ="\nDPID:"+self.dpid
        for row in self:
            repr+="\nNetwork:" + row.prefix.toStr() + "/" + str(row.mask) + ":\n"
            repr+=row.__repr__() + "\n"
        return repr

    def has_network(self,prefix,mask):
        for row in self:
            if row.prefix == prefix and row.mask == mask:
                return True
        return False

    def modify_column(self,dpid):
        keys = list()
        new_row = None
        for row in self:
            if row.desc == dpid:
                new_row = row
                for key,value in row.items():
                    row[key] = -1
                row[dpid] = 0
            else:
                if len(keys) == 0:
                    for key in row.keys():
                        keys.append(key)
                row[dpid] = -1
        if new_row is not None:
            for key in keys:
                new_row[key] = -1


class SRPFunction(object):

    def __init__(self):
        self.core_grid = dict()
        self.tor_grid = dict()

        # Listen to dependencies
        core.addListeners(self)
        def _listen_to_dependencies():
            core.BaseUtil.addListeners(self)
            core.LLDPUtil.addListeners(self)
        core.call_when_ready(_listen_to_dependencies, ('BaseUtil','LLDPUtil'))

    def _handle_GoingUpEvent(self, event):
        core.openflow.addListeners(self)
        log.debug("Up...")

    def _handle_ConnectionUp(self,event):
        dpid = dpid_to_str(event.dpid)

        if dpid in core.SRPConfig.core_list:
            self.core_grid[dpid] = SRPGrid(dpid)
        elif dpid in core.SRPConfig.tor_list:
            self.tor_grid[dpid] = SRPGrid(dpid)

        #将每个Tor对应的网段，加入到Core SRPGrid Row中,并将Tor加入到每个Row的Column中，并更新对应Column中的数字
        for tor_dpid in self.tor_grid.keys():
            host,mask = parse_cidr(core.SRPConfig.get_tor_lan_addr(tor_dpid))
            network= parse_network(host,mask)
            for core_dpid,core_rows in self.core_grid.items():
                if not core_rows.has_network(network,mask):
                    core_rows.append(SRPGrid_Row(tor_dpid,network,mask))
                    core_rows.modify_column(tor_dpid)
                    log.debug(core_rows)

        #for tor grid
        for core_dpid in self.core_grid.keys():
            for tor_dpid,tor_row in self.tor_grid.items():
                return


    def _handle_ConnectionDown(self,event):
        return

    def _handle_LinkEvent(self,event):
        return

    def _handle_IPv4In(self,event):
        return

def launch():
    core.registerNew(SRPFunction)


