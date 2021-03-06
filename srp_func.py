# coding:utf-8


from pox.core import core
from pox.lib.revent import EventMixin,Event
from collections import namedtuple
from pox.lib.util import dpid_to_str,str_to_bool,str_to_dpid
from pox.lib.revent import EventHalt,Event
from pox.lib.recoco import Timer
from pox.lib.addresses import parse_cidr,parse_prefix,same_network
from pox.lib.addresses import IPAddr

import time
import datetime
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt


#Global Var
log = core.getLogger()
FLOW_IDLE_TIMEOUT = of.OFP_FLOW_PERMANENT   #由SRP算法算出的流表，超时时间设置为无穷大，永久有效，除非手动修改
MAX_BUFFERED_PER_NETWORK = 5                #Datapath为每个未知的目的IP地址缓存多少个报文
MAX_BUFFER_TIME = 5                         #Buffer的超时时间

class Debug_Event(Event):

    def __init__(self,dpid):
        self.dpid = dpid


class SRPGrid_Row(dict):

    def __init__(self,dpid,prefix,mask):
        super(dict,self).__init__()
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
        super(list,self).__init__()
        self.dpid = dpid
        self.port = dict() #通往对端DPID的本端Port字典

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
        self.ipv4_buffers = dict()
        core.Interactive.variables["core_grid"] = self.core_grid
        core.Interactive.variables["tor_grid"] = self.tor_grid

        #For Debug
        core.Interactive.variables["scup"] = self._handle_debug_ConnectionUp
        core.Interactive.variables["scdown"] = self._handle_debug_ConnectionDown

        # 定义IPv4 Buffer超时计时器
        self._expire_ipv4_buffer_timer = Timer(5, self._handle_ipv4_buffer_expiration,recurring=True)

        #Listen to dependencies
        core.addListeners(self)
        def _listen_to_dependencies():
            core.BaseUtil.addListeners(self,priority=50)
            core.LLDPUtil.addListeners(self)
        core.call_when_ready(_listen_to_dependencies, ('BaseUtil','LLDPUtil'))

    def _handle_debug_ConnectionUp(self,dpid):
        ev = Debug_Event(str_to_dpid(dpid))
        self._handle_ConnectionUp(ev)

    def _handle_debug_ConnectionDown(self,dpid):
        ev = Debug_Event(str_to_dpid(dpid))
        self._handle_ConnectionDown(ev)

    def _handle_GoingUpEvent(self, event):
        core.openflow.addListeners(self,priority=50)
        log.debug("Up...")

    def _handle_ConnectionUp(self,event):
        dpid = dpid_to_str(event.dpid)

        #清空switch的所有之前的非法流表
        msg  = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        event.connection.send(msg)

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
        log.debug("[%s] Handle ConnectionDown Event!",dpid)

        #失联的是Core
        if dpid in core.SRPConfig.core_list:
            if dpid in self.core_grid:

                #删除失联的Core的Core_grid
                del self.core_grid[dpid]

                #删除其他Tor DPID对应的Tor_grid的相应列
                for tor_rows in self.tor_grid.values():
                    tor_rows.del_column(dpid)
                    #重新计算下发流表
                    for tor_row in tor_rows:
                        pos = list()
                        first_dpid = None
                        for tmp_dpid in tor_row.keys():
                            pos.append(str_to_dpid(tmp_dpid))
                        pos.sort()
                        for tmp_dpid in pos:
                            if tor_row[dpid_to_str(tmp_dpid)] == 1:
                                first_dpid = dpid_to_str(tmp_dpid)
                                break
                        if first_dpid is not None:
                            #删除旧流表
                            match = of.ofp_match()
                            match.dl_type = pkt.ethernet.IP_TYPE
                            match.nw_dst = tor_row.prefix.toStr() + "/" + str(tor_row.mask)
                            msg = of.ofp_flow_mod(command = of.OFPFC_DELETE,
                                                  match = match)
                            core.openflow.sendToDPID(str_to_dpid(tor_rows.dpid),msg)

                            #下发新流表
                            match = of.ofp_match()
                            match.dl_type = pkt.ethernet.IP_TYPE
                            match.nw_dst = tor_row.prefix.toStr() + "/" + str(tor_row.mask)
                            actions = list()
                            actions.append(of.ofp_action_output(port = tor_rows.port[first_dpid]))
                            msg = of.ofp_flow_mod(command = of.OFPFC_ADD,
                                                  match = match,
                                                  actions = actions,
                                                  idle_timeout = FLOW_IDLE_TIMEOUT,
                                                  hard_timeout = of.OFP_FLOW_PERMANENT)
                            core.openflow.sendToDPID(str_to_dpid(tor_rows.dpid),msg)
        #失联的是Tor
        elif dpid in core.SRPConfig.tor_list:
            if dpid in self.tor_grid:
                host,mask = parse_cidr(core.SRPConfig.get_tor_lan_addr(dpid))
                prefix = parse_prefix(host,mask)

                #删除失联Tor的Tor_grid
                del self.tor_grid[dpid]

                #删除所有Core DPID对应的Core_Grid的相应行和列
                for core_rows in self.core_grid.values():
                    core_rows.del_row(dpid,prefix,mask)
                    core_rows.del_column(dpid)

                    #因为Core只能从此断掉的Tor通往此Tor连接的网段，所以删除旧流表
                    match = of.ofp_match()
                    match.dl_type = pkt.ethernet.IP_TYPE
                    match.nw_dst = prefix.toStr() + "/" + str(mask)
                    msg = of.ofp_flow_mod(command = of.OFPFC_DELETE,
                                          match = match)
                    core.openflow.sendToDPID(str_to_dpid(core_rows.dpid),msg)

                #删除其他Tor DPID对应的Tor_Grid的相应行
                for tor_rows in self.tor_grid.values():
                    tor_rows.del_row(dpid,prefix,mask)
                    #因为只能从此断掉的Tor通往此Tor连接的网段，所以删除旧流表
                    match = of.ofp_match()
                    match.dl_type = pkt.ethernet.IP_TYPE
                    match.nw_dst = prefix.toStr() + "/" + str(mask)
                    msg = of.ofp_flow_mod(command = of.OFPFC_DELETE,
                                          match = match)
                    core.openflow.sendToDPID(str_to_dpid(tor_rows.dpid),msg)

    def _handle_LinkEvent(self,event):
        log.debug("[%s] Handle Link Event!",event.link)

        #寻找LinkEvent中dpid值对应的角色，并根据添加或删除连接事件属性作出相应的初始化或清理功能
        if dpid_to_str(event.link.dpid1) in core.SRPConfig.tor_list:
            tor_dpid,core_dpid = dpid_to_str(event.link.dpid1),dpid_to_str(event.link.dpid2)
            if event.added:
                #判断对应DPID的Grid是否已经建立，如果未建立则占时放弃处理LinkEvent，等待LinkEvent Timer超时以后重新触发
                if tor_dpid not in self.tor_grid or core_dpid not in self.core_grid:
                    event.used = False
                    return

                log.debug("[%s] Handle Link Up Event!",event.link)
                self.tor_grid[tor_dpid].port[core_dpid] = event.link.port1
                self.core_grid[core_dpid].port[tor_dpid] = event.link.port2

                #抑制Tor通往Core端口的广播功能
                con = core.openflow.getConnection(str_to_dpid(tor_dpid))
                for p in con.ports.itervalues():
                    if p.port_no == event.link.port1:
                        pm = of.ofp_port_mod(port_no=p.port_no,
                                             hw_addr=p.hw_addr,
                                             config =of.OFPPC_NO_FLOOD,
                                             mask = of.OFPPC_NO_FLOOD)
                        con.send(pm)
            elif event.removed:
                #判断如果LinkDown Event是伴随ConnectionDown Event的，则不做处理
                if tor_dpid not in self.tor_grid or core_dpid not in self.core_grid:
                    return

                log.debug("[%s] Handle Link Down Event!",event.link)
                self.tor_grid[tor_dpid].port[core_dpid] = None
                self.core_grid[core_dpid].port[tor_dpid] = None
        else:
            tor_dpid,core_dpid = dpid_to_str(event.link.dpid2),dpid_to_str(event.link.dpid1)
            if event.added:
                #判断对应DPID的Grid是否已经建立，如果未建立则占时放弃处理LinkEvent，等待LinkEvent Timer超时以后重新触发
                if tor_dpid not in self.tor_grid or core_dpid not in self.core_grid:
                    event.used = False
                    return

                log.debug("[%s] Handle Link Up Event!",event.link)
                self.tor_grid[tor_dpid].port[core_dpid] = event.link.port2
                self.core_grid[core_dpid].port[tor_dpid] = event.link.port1

                #抑制Tor通往Core端口的广播功能
                con = core.openflow.getConnection(str_to_dpid(tor_dpid))
                for p in con.ports.itervalues():
                    if p.port_no == event.link.port2:
                        pm = of.ofp_port_mod(port_no=p.port_no,
                                             hw_addr=p.hw_addr,
                                             config =of.OFPPC_NO_FLOOD,
                                             mask = of.OFPPC_NO_FLOOD)
                        con.send(pm)
            elif link.removed:
                #判断如果LinkDown Event是伴随ConnectionDown Event的，则不做处理
                if tor_dpid not in self.tor_grid or core_dpid not in self.core_grid:
                    return

                log.debug("[%s] Handle Link Down Event!",event.link)
                self.tor_grid[tor_dpid].port[core_dpid] = None
                self.core_grid[core_dpid].port[tor_dpid] = None

        if event.added:
            #更改此UP链路连接的Tor的Grid中UP链路链接的Core对应的状态值
            for tor_row in self.tor_grid[tor_dpid]:
                if core_dpid in tor_row:
                    if tor_row[core_dpid] % 2 == 0:
                        tor_row[core_dpid] += 1
                        #统计此core_dpid在此tor_grid中的位置
                        pos = list()
                        first = True
                        for dpid in tor_row.keys():
                            pos.append(str_to_dpid(dpid))
                        pos.sort()
                        for dpid in pos:
                            if tor_row[dpid_to_str(dpid)] == 1:
                                if dpid_to_str(dpid) == core_dpid:
                                    break
                                else:
                                    first = False
                                    break
                        #如果此core_dpid是状态为1的最前的dpid，则删除原流表并下发新流表，如果不是则不做处理
                        if first:
                            #删除旧流表
                            match = of.ofp_match()
                            match.dl_type = pkt.ethernet.IP_TYPE
                            match.nw_dst = tor_row.prefix.toStr() + "/" + str(tor_row.mask)
                            msg = of.ofp_flow_mod(command = of.OFPFC_DELETE,
                                                  match = match)
                            core.openflow.sendToDPID(str_to_dpid(tor_dpid),msg)

                            #下发新流表
                            match = of.ofp_match()
                            match.dl_type = pkt.ethernet.IP_TYPE
                            match.nw_dst = tor_row.prefix.toStr() + "/" + str(tor_row.mask)
                            actions = list()
                            actions.append(of.ofp_action_output(port = self.tor_grid[tor_dpid].port[core_dpid]))
                            msg = of.ofp_flow_mod(command = of.OFPFC_ADD,
                                                  match = match,
                                                  actions = actions,
                                                  idle_timeout = FLOW_IDLE_TIMEOUT,
                                                  hard_timeout = of.OFP_FLOW_PERMANENT)
                            core.openflow.sendToDPID(str_to_dpid(tor_dpid),msg)

            #更改此UP链路连接的Core的Grid中UP链路连接的Tor对应的状态值
            for core_row in self.core_grid[core_dpid]:
                if tor_dpid in core_row:
                    if core_row[tor_dpid] != -1 and core_row[tor_dpid] % 2 == 0:
                        core_row[tor_dpid] += 1
                        #下发新流表
                        match = of.ofp_match()
                        match.dl_type = pkt.ethernet.IP_TYPE
                        match.nw_dst = core_row.prefix.toStr()+'/'+str(core_row.mask)
                        actions = list()
                        actions.append(of.ofp_action_output(port = self.core_grid[core_dpid].port[tor_dpid]))
                        msg = of.ofp_flow_mod(command = of.OFPFC_ADD,
                                              match = match,
                                              actions = actions,
                                              idle_timeout = FLOW_IDLE_TIMEOUT,
                                              hard_timeout = of.OFP_FLOW_PERMANENT)
                        core.openflow.sendToDPID(str_to_dpid(core_dpid),msg)

                        #更新其他的受影响的Tor的Grid
                        for tor_rows in self.tor_grid.values():
                            if tor_rows.dpid == tor_dpid:
                                continue
                            for tor_row in tor_rows:
                                if tor_row.dpid == tor_dpid and tor_row.prefix == core_row.prefix and tor_row.mask == core_row.mask:
                                    if tor_row[core_dpid] % 2 != 0:
                                        continue

                                    if core_dpid in tor_rows.port:
                                        tor_row[core_dpid] += 1

                                    #统计此core_dpid在此tor_grid中的位置
                                    pos = list()
                                    first = True
                                    for dpid in tor_row.keys():
                                        pos.append(str_to_dpid(dpid))
                                    pos.sort()
                                    for dpid in pos:
                                        if tor_row[dpid_to_str(dpid)] == 1:
                                            if dpid_to_str(dpid) == core_dpid:
                                                break
                                            else:
                                                first = False
                                                break
                                    #如果此core_dpid是状态为1的最前的dpid，则删除原流表并下发新流表，如果不是则不做处理
                                    if first:
                                        if core_dpid in tor_row and core_dpid in tor_rows.port:
                                            if tor_rows.port[core_dpid] is not None:
                                                #删除旧流表
                                                match = of.ofp_match()
                                                match.dl_type = pkt.ethernet.IP_TYPE
                                                match.nw_dst = tor_row.prefix.toStr() + "/" + str(tor_row.mask)
                                                msg = of.ofp_flow_mod(command = of.OFPFC_DELETE,
                                                                      match = match)
                                                core.openflow.sendToDPID(str_to_dpid(tor_rows.dpid),msg)

                                                #下发新流表
                                                match = of.ofp_match()
                                                match.dl_type = pkt.ethernet.IP_TYPE
                                                match.nw_dst = tor_row.prefix.toStr() + "/" + str(tor_row.mask)
                                                actions = list()
                                                actions.append(of.ofp_action_output(port = tor_rows.port[core_dpid]))
                                                msg = of.ofp_flow_mod(command = of.OFPFC_ADD,
                                                                      match = match,
                                                                      actions = actions,
                                                                      idle_timeout = FLOW_IDLE_TIMEOUT,
                                                                      hard_timeout = of.OFP_FLOW_PERMANENT)
                                                core.openflow.sendToDPID(str_to_dpid(tor_rows.dpid),msg)
        elif event.removed:
            #更改此断掉链路原连接的Core的Grid中断掉链路原链接的Tor对应的状态值
            for core_row in self.core_grid[core_dpid]:
                if tor_dpid in core_row:
                    #判断此行是来自于断掉的链路连接的Tor的且之前的状态不是0
                    if core_row[tor_dpid] != -1 and core_row[tor_dpid] % 2 == 1:
                        core_row[tor_dpid] -= 1

                        #删除此Core上无效的流表
                        match = of.ofp_match()
                        match.dl_type = pkt.ethernet.IP_TYPE
                        match.nw_dst = core_row.prefix.toStr() + "/" + str(core_row.mask)
                        msg = of.ofp_flow_mod(command = of.OFPFC_DELETE,
                                              match = match)
                        core.openflow.sendToDPID(str_to_dpid(core_dpid),msg)

                        #更新其他的受影响的Tor的Grid
                        for tor_rows in self.tor_grid.values():
                            if tor_rows.dpid == tor_dpid:
                                continue
                            for tor_row in tor_rows:
                                if tor_row.dpid == tor_dpid and tor_row.prefix == core_row.prefix and tor_row.mask == core_row.mask:
                                    if tor_row[core_dpid] % 2 != 1:
                                        continue
                                    tor_row[core_dpid] -= 1

                                    #统计此core_dpid在此tor_grid中的位置
                                    pos = list()
                                    first = True
                                    next = False
                                    for dpid in tor_row.keys():
                                        pos.append(str_to_dpid(dpid))
                                    pos.sort()
                                    for dpid in pos:
                                        if dpid_to_str(dpid) == core_dpid:
                                            #此时此core_dpid之前没有值为1，要寻找下一个值为1的core_dpid
                                            next = True
                                        elif tor_row[dpid_to_str(dpid)] == 1:
                                            if not next:
                                                #此时此core_dpid之前还有值为1，则不用修改流表
                                                first = False
                                                break
                                            else:
                                                #找到了下一个值为1的core_dpid，记录其位置
                                                next = dpid_to_str(dpid)
                                                break

                                    #此时此core_dpid之前没有值为1
                                    if first:
                                        #此时整行都没有值为1，只用将原流表删除
                                        if next is True:
                                            match = of.ofp_match()
                                            match.dl_type = pkt.ethernet.IP_TYPE
                                            match.nw_dst = tor_row.prefix.toStr() + "/" + str(tor_row.mask)
                                            msg = of.ofp_flow_mod(command = of.OFPFC_DELETE,
                                                                  match = match)
                                            core.openflow.sendToDPID(str_to_dpid(tor_dpid),msg)
                                        #在此core_dpid之后还有1，则要删除之前的流表，并下发新的流表
                                        else:
                                            #删除旧流表
                                            match = of.ofp_match()
                                            match.dl_type = pkt.ethernet.IP_TYPE
                                            match.nw_dst = tor_row.prefix.toStr() + "/" + str(tor_row.mask)
                                            msg = of.ofp_flow_mod(command = of.OFPFC_DELETE,
                                                                  match = match)
                                            core.openflow.sendToDPID(str_to_dpid(tor_rows.dpid),msg)

                                            #下发新流表
                                            if tor_rows.port[next] is not None:
                                                match = of.ofp_match()
                                                match.dl_type = pkt.ethernet.IP_TYPE
                                                match.nw_dst = tor_row.prefix.toStr() + "/" + str(tor_row.mask)
                                                actions = list()
                                                actions.append(of.ofp_action_output(port = tor_rows.port[next]))
                                                msg = of.ofp_flow_mod(command = of.OFPFC_ADD,
                                                                      match = match,
                                                                      actions = actions,
                                                                      idle_timeout = FLOW_IDLE_TIMEOUT,
                                                                      hard_timeout = of.OFP_FLOW_PERMANENT)
                                                core.openflow.sendToDPID(str_to_dpid(tor_rows.dpid),msg)

            #更改此断掉链路原连接的Tor的Grid中断掉链路原链接的Core对应的状态值
            for tor_row in self.tor_grid[tor_dpid]:
                if core_dpid in tor_row:
                    if tor_row[core_dpid] % 2 == 1:
                        tor_row[core_dpid] -= 1
                        #统计此core_dpid在此tor_grid中的位置
                        pos = list()
                        first = True
                        next = False
                        for dpid in tor_row.keys():
                            pos.append(str_to_dpid(dpid))
                        pos.sort()
                        for dpid in pos:
                            if dpid_to_str(dpid) == core_dpid:
                            #此时此core_dpid之前没有值为1，要寻找下一个值为1的core_dpid
                                next = True
                            elif tor_row[dpid_to_str(dpid)] == 1:
                                if not next:
                                #此时此core_dpid之前还有值为1，则不用修改流表
                                    first = False
                                    break
                                else:
                                    #找到了下一个值为1的core_dpid，记录其位置
                                    next = dpid_to_str(dpid)
                                    break

                        #此时此core_dpid之前没有值为1
                        if first:
                            #此时整行都没有值为1，只用将原流表删除
                            if next is True:
                                match = of.ofp_match()
                                match.dl_type = pkt.ethernet.IP_TYPE
                                match.nw_dst = tor_row.prefix.toStr() + "/" + str(tor_row.mask)
                                msg = of.ofp_flow_mod(command = of.OFPFC_DELETE,
                                                      match = match)
                                core.openflow.sendToDPID(str_to_dpid(tor_dpid),msg)
                                #在此core_dpid之后还有1，则要删除之前的流表，并下发新的流表
                            else:
                                #删除旧流表
                                match = of.ofp_match()
                                match.dl_type = pkt.ethernet.IP_TYPE
                                match.nw_dst = tor_row.prefix.toStr() + "/" + str(tor_row.mask)
                                msg = of.ofp_flow_mod(command = of.OFPFC_DELETE,
                                                      match = match)
                                core.openflow.sendToDPID(str_to_dpid(tor_dpid),msg)

                                #下发新流表
                                if self.tor_grid[tor_dpid].port[next] is not None:
                                    match = of.ofp_match()
                                    match.dl_type = pkt.ethernet.IP_TYPE
                                    match.nw_dst = tor_row.prefix.toStr() + "/" + str(tor_row.mask)
                                    actions = list()
                                    actions.append(of.ofp_action_output(port = self.tor_grid[tor_dpid].port[next]))
                                    msg = of.ofp_flow_mod(command = of.OFPFC_ADD,
                                                          match = match,
                                                          actions = actions,
                                                          idle_timeout = FLOW_IDLE_TIMEOUT,
                                                          hard_timeout = of.OFP_FLOW_PERMANENT)
                                    core.openflow.sendToDPID(str_to_dpid(tor_dpid),msg)

    def _handle_ipv4_buffer_expiration(self):
        empty = []
        for k, v in self.ipv4_buffers.iteritems():
            dpid, ip = k
            for item in list(v):
                expires_at, buffer_id, in_port = item
                if expires_at < time.time():
                    v.remove(item)
                    #不为packet out消息指定outport action，则默认使DPID丢弃该报文
                    msg = of.ofp_packet_out(buffer_id=buffer_id, in_port=in_port)
                    core.openflow.sendToDPID(str_to_dpid(dpid), msg)
            if len(v) == 0:
                empty.append(k)
        for k in empty:
            del self.ipv4_buffers[k]

    def _send_ipv4_buffer(self,dpid,dst_ip,outport):
        if (dpid,dst_ip) in self.ipv4_buffers:
            log.debug("[%s] Send buffered ipv4 packets to %s",dpid,dst_ip)
            buffers = self.ipv4_buffers[(dpid,dst_ip)]
            del self.ipv4_buffers[(dpid,dst_ip)]
            for entry in buffers:
                msg = of.ofp_packet_out(buffer_id=entry[1],in_port=entry[2])
                msg.actions.append(of.ofp_action_output(port=outport))
                core.openflow.sendToDPID(str_to_dpid(dpid),msg)

    def _handle_IPv4In(self,event):
        dst_ip = event.ipv4p.dstip
        dpid = dpid_to_str(event.connection.dpid)
        inport = event.inport

        #判断是否是Core收到了IPv4In事件
        if dpid in core.SRPConfig.tor_list:
            #判断目的网段是否在对应DPID连接的网段中
            if same_network(dst_ip,core.SRPConfig.get_tor_lan_addr(dpid)):
                return

            for tor_row in self.tor_grid[dpid]:
                if same_network(dst_ip,tor_row.prefix.toStr()+"/"+str(tor_row.mask)):
                    pos = list()
                    first_dpid = None
                    for tmp_dpid in tor_row.keys():
                        pos.append(str_to_dpid(tmp_dpid))
                    pos.sort()
                    for tmp_dpid in pos:
                        if tor_row[dpid_to_str(tmp_dpid)] == 1:
                            first_dpid = dpid_to_str(tmp_dpid)
                            break
                    #如果当前SRP已经计算出可用路径
                    if first_dpid is not None:

                        #按照可用路径发出此包
                        log.debug("[%s] Send out the ipv4 packet: %s =>%s",dpid,event.ipv4p.srcip,dst_ip)
                        msg = of.ofp_packet_out(buffer_id = event.ofp.buffer_id, in_port = inport)
                        msg.actions.append(of.ofp_action_output(port = self.tor_grid[dpid].port[first_dpid]))
                        core.openflow.sendToDPID(str_to_dpid(dpid),msg)

                        #发送之前缓存的IPv4报文
                        self._send_ipv4_buffer(dpid,dst_ip,self.tor_grid[dpid].port[first_dpid])

                        #下发新流表
                        log.debug("[%s] Set up the Flow for destination: %s",dpid,dst_ip)
                        match = of.ofp_match()
                        match.dl_type = pkt.ethernet.IP_TYPE
                        match.nw_dst = tor_row.prefix.toStr() + "/" + str(tor_row.mask)
                        actions = list()
                        actions.append(of.ofp_action_output(port = tor_rows.port[first_dpid]))
                        msg = of.ofp_flow_mod(command = of.OFPFC_ADD,
                                              match = match,
                                              actions = actions,
                                              idle_timeout = FLOW_IDLE_TIMEOUT,
                                              hard_timeout = of.OFP_FLOW_PERMANENT)
                        core.openflow.sendToDPID(str_to_dpid(dpid),msg)
                    else:
                        if (dpid,dst_ip) not in self.ipv4_buffers:
                            self.ipv4_buffers[(dpid,dst_ip)] = []
                        buffers  = self.ipv4_buffers[(dpid,dst_ip)]
                        entry = (time.time()+MAX_BUFFER_TIME,event.ofp.buffer_id,inport)
                        buffers.append(entry)
                        #超出最大Buffer数量，则从最老得开始丢弃
                        while len(buffers)>MAX_BUFFERED_PER_NETWORK:
                            msg = of.ofp_packet_out(buffer_id=buffers[0][1],in_port=buffers[0][2])
                            core.openflow.sendToDPID(str_to_dpid(dpid),msg)
                            del buffers[0]


def launch():
    core.registerNew(SRPFunction)


