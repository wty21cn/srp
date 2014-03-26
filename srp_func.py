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
from pox.lib.util import dpid_to_str,str_to_bool,str_to_dpid
from pox.lib.revent import EventHalt,Event
from pox.lib.recoco import Timer
from pox.lib.addresses import parse_cidr,parse_prefix

import time
import datetime
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt


#Global Var
log = core.getLogger()

class Debug_Event(Event):

    def __init__(self,dpid):
        self.dpid = dpid


class SRPGrid_Row(dict):

    def __init__(self,dpid,prefix,mask):
        dict.__init__({})
        self.dpid = dpid
        self.prefix = prefix
        self.mask  = mask

    def __repr__(self):
        return self.dpid + ": "+dict.__repr__(self)


class SRPGrid_Set(dict):

    def __repr__(self):
        repr = ""
        for grid in self.values():
            repr += "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
            repr += grid.__repr__()
            repr += "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n"
        return repr


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

    def add_core_column(self,dpid):
        keys = list()
        new_row = None
        for row in self:
            if row.dpid == dpid:
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

    def add_tor_column(self,dpid):
        for row in self:
            if dpid not in row:
                row[dpid] = 0

    def del_column(self,dpid):
        for row in self:
            if dpid in row:
                del row[dpid]

    def del_row(self,dpid,prefix,mask):
        del_list = list()
        for pos in range(len(self)):
            if self[pos].dpid == dpid and self[pos].prefix == prefix and self[pos].mask == mask:
                del_list.append(pos)
        for pos in del_list:
            del self[pos]


class SRPFunction(object):

    def __init__(self):
        self.core_grid = SRPGrid_Set()
        self.tor_grid = SRPGrid_Set()
        core.Interactive.variables["core_grid"] = self.core_grid
        core.Interactive.variables["tor_grid"] = self.tor_grid

        #For Debug
        core.Interactive.variables["srpcup"] = self._handle_debug_ConnectionUp
        core.Interactive.variables["srpcdown"] = self._handle_debug_ConnectionDown

        #Listen to dependencies
        core.addListeners(self)
        def _listen_to_dependencies():
            core.BaseUtil.addListeners(self)
            core.LLDPUtil.addListeners(self)
        core.call_when_ready(_listen_to_dependencies, ('BaseUtil','LLDPUtil'))

    def _handle_debug_ConnectionUp(self,dpid):
        ev = Debug_Event(str_to_dpid(dpid))
        self._handle_ConnectionUp(ev)

    def _handle_debug_ConnectionDown(self,dpid):
        ev = Debug_Event(str_to_dpid(dpid))
        self._handle_ConnectionDown(ev)

    def _handle_GoingUpEvent(self, event):
        core.openflow.addListeners(self)
        log.debug("Up...")

    def _handle_ConnectionUp(self,event):
        dpid = dpid_to_str(event.dpid)

        if dpid in core.SRPConfig.core_list:
            if dpid in self.core_grid:
                del self.core_grid[dpid]
            self.core_grid[dpid] = SRPGrid(dpid)
        elif dpid in core.SRPConfig.tor_list:
            if dpid in self.tor_grid:
                del self.tor_grid[dpid]
            self.tor_grid[dpid] = SRPGrid(dpid)

        #将每个Tor对应的网段，加入到Core SRPGrid Row中,并将Tor加入到每个Row的Column中，并更新对应Column中的初始值
        for tor_dpid in self.tor_grid.keys():
            host,mask = parse_cidr(core.SRPConfig.get_tor_lan_addr(tor_dpid))
            prefix= parse_prefix(host,mask)
            for core_dpid,core_rows in self.core_grid.items():
                if not core_rows.has_network(prefix,mask):
                    core_rows.append(SRPGrid_Row(tor_dpid,prefix,mask))
                    core_rows.add_core_column(tor_dpid)

        #将Core能到达的网段加入它所连接的每一个Tor，将Core加入到相应Row的Column中，并更新对应Column中的初始值
        for core_dpid,core_rows in self.core_grid.items():
            for row in core_rows:
                prefix  = row.prefix
                mask = row.mask
                dpid = row.dpid
                for tor_dpid,tor_rows in self.tor_grid.items():
                    if not tor_rows.has_network(prefix,mask):
                        if tor_dpid != dpid:
                            tor_rows.append(SRPGrid_Row(dpid,prefix,mask))
                    tor_rows.add_tor_column(core_dpid)

    def _handle_ConnectionDown(self,event):
        dpid = dpid_to_str(event.dpid)

        if dpid in core.SRPConfig.core_list:
            if dpid in self.core_grid:
                del self.core_grid[dpid]
                for tor_rows in self.tor_grid.values():
                    tor_rows.del_column(dpid)
        elif dpid in core.SRPConfig.tor_list:
            if dpid in self.tor_grid:
                host,mask = parse_cidr(core.SRPConfig.get_tor_lan_addr(dpid))
                prefix = parse_prefix(host,mask)

                #删除失联Tor的Tor_grid
                del self.tor_grid[dpid]

                #清楚所有DPID对应的Core_Grid的相应行
                for core_rows in self.core_grid.values():
                    core_rows.del_row(dpid,prefix,mask)

                    #清楚所有DPID对应的Tor_Grid的相应行
                    for tor_rows in self.tor_grid.values():
                        tor_rows.del_row(dpid,prefix,mask)

    def _handle_LinkEvent(self,event):
        return

    def _handle_IPv4In(self,event):
        return

def launch():
    core.registerNew(SRPFunction)


