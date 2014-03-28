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

"""

"""

from pox.core import core
from pox.lib.revent import EventMixin,Event
from collections import namedtuple
from pox.lib.util import dpid_to_str,str_to_bool
from pox.lib.revent import EventHalt
from pox.lib.recoco import Timer

import time
import datetime
import struct
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt


#Global Var
log = core.getLogger()
VALIDATE_LINK_TIMEOUT = 20
DELETE_LINK_TIMEOUT = 35
SEND_CYCLE = 1
SEND_LLDP_CYCLE_INTERVAL = 2
RAISE_LINK_EVENT_CYCLE_INTERVAL = 1

TTL = 120

class Link(namedtuple("LinkBase", ("dpid1", "port1", "dpid2", "port2"))):

    @property
    def uni(self):
        """
        返回单向表示的链路，DPID小的放在前端
        """
        pairs = list(self.ends)
        pairs.sort()
        return Link(pairs[0][0], pairs[0][1], pairs[1][0], pairs[1][1])

    @property
    def ends(self):
        return (self.dpid1, self.port1), (self.dpid2, self.port2)

    def is_connect_to_dpid(self,dpid):
            return False if dpid != self.dpid1 and dpid != self.dpid2 else True

    def is_connect_to_dpid_port(self,dpid,port):
        if dpid == self.dpid1:
            return True if port == self.port1 else False
        if dpid == self.dpid2:
            return True if port == self.port2 else False
        return False

    def __str__(self):
        return "%s.%s -> %s.%s" % (dpid_to_str(self[0]), self[1],
                                   dpid_to_str(self[2]), self[3])

    def __repr__(self):
        return "Link(dpid1=%s,port1=%s, dpid2=%s,port2=%s)" % (self.dpid1,
                                                               self.port1, self.dpid2, self.port2)


class Adjacency(dict):

    def __repr__(self):
        repr = list()
        for link,timestamp in self.items():
            repr.append(link.__str__())
        return "\n".join(repr)


class LinkEvent(Event):

    """
    Link up/down event
    """

    def __init__(self, add, link):
        Event.__init__(self)
        self.link = link
        self.added = add
        self.removed = not add
        self.used = True

    def port_for_dpid(self, dpid):
        if self.link.dpid1 == dpid:
            return self.link.port1
        if self.link.dpid2 == dpid:
            return self.link.port2
        return None


class LLDPUtil(EventMixin):

    _eventMixin_events = set([LinkEvent])

    SendItem = namedtuple("LLDPSenderItem", ('dpid', 'port_num', 'packet'))
    Link = Link

    def __init__(self,no_flows,explicit_drop,validate_link_timeout,delete_link_timeout,flow_priority,ttl,send_cycle,send_lldp_cycle_interval,raise_link_event_cycle_interval):
        self.install_flow = not no_flows
        self.explicit_drop = explicit_drop
        self.validate_link_timeout = validate_link_timeout
        self.delete_link_timeout = delete_link_timeout
        self.flow_priority = flow_priority
        self.ttl = ttl
        self.send_cycle = send_cycle
        self.send_lldp_cycle_interval = send_lldp_cycle_interval
        self.raise_link_event_cycle_interval = raise_link_event_cycle_interval
        self.adjacency = Adjacency()
        self._set_link_validate_timer(validate_link_timeout)
        self.port_addr = dict()
        core.addListeners(self)
        core.Interactive.variables["link"] = self.adjacency

    def _install_flow(self,connection,priority=None):
        if priority is None:
            priority = self.flow_priority
        match = of.ofp_match(dl_type=pkt.ethernet.LLDP_TYPE,
                             dl_dst=pkt.ETHERNET.NDP_MULTICAST)
        msg = of.ofp_flow_mod()
        msg.priority = priority
        msg.match = match
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        connection.send(msg)

    def _parse_lldp(self,lldph,in_dpid,in_port):
        if lldph is None or not lldph.parsed:
            log.error("LLDP packet could not be parsed")
            return None,None,EventHalt
        if len(lldph.tlvs) < 3:
            log.error("LLDP packet without required three TLVs")
            return None,None,EventHalt
        if lldph.tlvs[0].tlv_type != pkt.lldp.CHASSIS_ID_TLV:
            log.error("LLDP packet TLV 1 not CHASSIS_ID")
            return None,None,EventHalt
        if lldph.tlvs[1].tlv_type != pkt.lldp.PORT_ID_TLV:
            log.error("LLDP packet TLV 2 not PORT_ID")
            return None,None,EventHalt
        if lldph.tlvs[2].tlv_type != pkt.lldp.TTL_TLV:
            log.error("LLDP packet TLV 3 not TTL")
            return None,None,EventHalt

        def lookInSysDesc():
            for t in lldph.tlvs[3:]:
                if t.tlv_type == pkt.lldp.SYSTEM_DESC_TLV:
                    for line in t.payload.split('\n'):
                        if line.startswith('dpid:'):
                            try:
                                return int(line[5:], 16)
                            except:
                                pass
                    return None
        originatorDPID = lookInSysDesc()
        if originatorDPID is None:
            # We'll look in the CHASSIS ID
            if lldph.tlvs[0].subtype == pkt.chassis_id.SUB_LOCAL:
                if lldph.tlvs[0].id.startswith('dpid:'):
                    # This is how NOX does it at the time of writing
                    try:
                        originatorDPID = int(lldph.tlvs[0].id[5:], 16)
                    except:
                        pass
            if originatorDPID is None:
                if lldph.tlvs[0].subtype == pkt.chassis_id.SUB_MAC:
                    # Last ditch effort -- we'll hope the DPID was small enough
                    # to fit into an ethernet address
                    if len(lldph.tlvs[0].id) == 6:
                        try:
                            s = lldph.tlvs[0].id
                            originatorDPID = struct.unpack("!Q", '\x00\x00' + s)[0]
                        except:
                            pass
        if originatorDPID is None:
            log.warning("Couldn't find a DPID in the LLDP packet")
            return None,None,EventHalt
        if originatorDPID not in core.openflow.connections:
            log.info('Received LLDP packet from unknown switch')
            return None,None,EventHalt


        if lldph.tlvs[1].subtype != pkt.port_id.SUB_PORT:
            log.warning(
                "Thought we found a DPID, but packet didn't have a port")
            return None,None,EventHalt
        originatorPort = None
        if lldph.tlvs[1].id.isdigit():
            originatorPort = int(lldph.tlvs[1].id)
        elif len(lldph.tlvs[1].id) == 2:
            try:
                originatorPort = struct.unpack("!H", lldph.tlvs[1].id)[0]
            except:
                pass
        if originatorPort is None:
            log.warning("Thought we found a DPID, but port number didn't make sense")
            return None,None,EventHalt
        if (in_dpid, in_port) == (originatorDPID, originatorPort):
            log.warning("Port received its own LLDP packet; ignoring")
            return None,None,EventHalt

        return originatorDPID, originatorPort, None

    def _send_lldp_buffer(self,lldp_buffer,times):
        dpids = list()
        for packet in lldp_buffer:
            if packet.dpid not in dpids:
                dpids.append(packet.dpid)
        for dpid in dpids:
            log.debug("[%s] Send lldp buffer! ",dpid_to_str(dpid))

        for item in lldp_buffer:
            core.openflow.sendToDPID(item.dpid,item.packet)
        if times == self.send_cycle:
            del lldp_buffer[:]

    def _create_lldp_packet(self,dpid,port_num,port_addr):
        chassis_id = pkt.chassis_id(subtype=pkt.chassis_id.SUB_LOCAL)
        chassis_id.id = bytes('dpid:' + hex(long(dpid))[2:-1])

        port_id = pkt.port_id(subtype=pkt.port_id.SUB_PORT, id=str(port_num))

        ttl = pkt.ttl(ttl=self.ttl)

        sysdesc = pkt.system_description()
        sysdesc.payload = bytes('dpid:' + hex(long(dpid))[2:-1])

        discovery_packet = pkt.lldp()
        discovery_packet.tlvs.append(chassis_id)
        discovery_packet.tlvs.append(port_id)
        discovery_packet.tlvs.append(ttl)
        discovery_packet.tlvs.append(sysdesc)
        discovery_packet.tlvs.append(pkt.end_tlv())

        eth = pkt.ethernet(type=pkt.ethernet.LLDP_TYPE)
        eth.src = port_addr
        eth.dst = pkt.ETHERNET.NDP_MULTICAST
        eth.payload = discovery_packet

        msg = of.ofp_packet_out(action=of.ofp_action_output(port=port_num))
        msg.data = eth.pack()
        return msg.pack()

    def _delete_link(self,dpid,port=None):
        if port is not None:
            delete_link = None
            for link in self.adjacency:
                if link.is_connect_to_dpid_port(dpid,port):
                    delete_link = link
                    break
            if delete_link is not None:
                log.debug("Remove Link %s!",delete_link)
                self.adjacency.pop(delete_link,None)
                ev = LinkEvent(False,delete_link)
                self.raiseEvent(ev)
        else:
            delete_link = list()
            for link in self.adjacency:
                if link.is_connect_to_dpid(dpid):
                    delete_link.append(link)
            for link in delete_link:
                log.debug("Remove Link %s!",link)
                self.adjacency.pop(link,None)
                ev = LinkEvent(False,link)
                self.raiseEvent(ev)

    def _set_send_lldp_timer(self,lldp_buffer):
        for i in range(self.send_cycle):
            arg = (lldp_buffer,i)
            Timer(self.send_lldp_cycle_interval*i,self._send_lldp_buffer,absoluteTime=False,recurring=False,args = arg)

    def _set_link_validate_timer(self,validate_time):
        Timer(validate_time,self._handle_link_validate_timer,recurring=True)
        
    def _handle_raise_link_event_timer(self,event):
        self.raiseEvent(event)
        log.info('Link detected: %s', event.link)
        if event.used:
            return False

    def _set_raise_link_event_timer(self,event):
        Timer(self.raise_link_event_cycle_interval,self._handle_raise_link_event_timer,recurring=True,args = (event,))

    def _handle_link_validate_timer(self):
        lldp_buffer = list()
        now = time.time()
        for link,timestamp in self.adjacency.items():
            dpid = link.dpid1
            port = link.port1
            if timestamp + self.delete_link_timeout < now:
                self._delete_link(dpid,port)
            else:
                lldp = self._create_lldp_packet(dpid,port,self.port_addr[dpid][port])
                lldp_buffer.append(LLDPUtil.SendItem(dpid,port,lldp))
        if len(lldp_buffer)>0:
            self._set_send_lldp_timer(lldp_buffer)

    def _handle_ConnectionUp(self,event):
        if self.install_flow:
            log.debug("[%s] Installing flow for LLDP packet", dpid_to_str(event.dpid))
            self._install_flow(event.connection)

        ports = [(p.port_no, p.hw_addr) for p in event.ofp.ports]
        lldp_buffer = list()
        if event.dpid not in self.port_addr:
            self.port_addr[event.dpid] = dict()
        for port_num,port_addr in ports:
            if port_num not in self.port_addr[event.dpid]:
                self.port_addr[event.dpid][port_num] = port_addr
            lldp = self._create_lldp_packet(event.dpid,port_num,port_addr)
            lldp_buffer.append(LLDPUtil.SendItem(event.dpid,port_num,lldp))

        self._set_send_lldp_timer(lldp_buffer)

    def _handle_ConnectionDown(self,event):
        if event.dpid in self.port_addr:
            self.port_addr[event.dpid].clear()
        self._delete_link(event.dpid)

    def _handle_GoingUpEvent(self,event):
        core.openflow.addListeners(self)
        log.debug("Up...")
        return

    def _handle_PortStatus(self,event):
        if event.added or (event.modified and event.ofp.desc.config is 0x00000000 and event.ofp.desc.state is 0x00000000):
            log.debug("[%s] Port %i is up!",dpid_to_str(event.dpid),event.port)
            lldp_buffer = list()
            lldp  = self._create_lldp_packet(event.dpid,event.port,event.ofp.desc.hw_addr)
            lldp_buffer.append(LLDPUtil.SendItem(event.dpid,event.port,lldp))
            self._set_send_lldp_timer(lldp_buffer)
        elif event.deleted or (event.modified and (event.ofp.desc.config is 0x0000001 or event.ofp.desc.state is 0x00000001)):
            log.debug("[%s] Port %i is down!",dpid_to_str(event.dpid),event.port)
            self._delete_link(event.dpid,event.port)

    def _handle_PacketIn(self,event):
        packet = event.parsed

        #判断是否为LLDP报文
        if (packet.effective_ethertype != pkt.ethernet.LLDP_TYPE
            or packet.dst != pkt.ETHERNET.NDP_MULTICAST):
            return

        if self.explicit_drop:
            #指定DPID丢弃缓存的LLDP报文
            if event.ofp.buffer_id is not None:
                log.debug("[%s] Dropping LLDP packet %i", dpid_to_str(event.dpid), event.ofp.buffer_id)
                msg = of.ofp_packet_out()
                msg.buffer_id = event.ofp.buffer_id
                msg.in_port = event.port
                event.connection.send(msg)

        lldph = packet.find(pkt.lldp)
        originatorDPID,originatorPort,Err = self._parse_lldp(lldph,event.dpid,event.port)
        if Err is EventHalt:
            return Err

        #构建无向Link、存入Adjacency集合，并触发LinkUpEvent
        link = Link(originatorDPID, originatorPort, event.dpid, event.port).uni
        if link not in self.adjacency:
            self.adjacency[link] = time.time()
            ev = LinkEvent(True,link)
            self._set_raise_link_event_timer(ev)
        else:
            self.adjacency[link] = time.time()


def launch(no_flows=False,
           explicit_drop=True,
           validate_link_timeout=VALIDATE_LINK_TIMEOUT,
           delete_link_timeout=DELETE_LINK_TIMEOUT,
           flow_priority = 65500,
           ttl = TTL,
           send_cycle = SEND_CYCLE,
           send_lldp_cycle_interval = SEND_LLDP_CYCLE_INTERVAL,
           raise_link_event_cycle_interval = RAISE_LINK_EVENT_CYCLE_INTERVAL):

    core.registerNew(LLDPUtil,
                     str_to_bool(no_flows),
                     str_to_bool(explicit_drop),
                     int(validate_link_timeout),
                     int(delete_link_timeout),
                     int(flow_priority),
                     ttl,
                     send_cycle,
                     send_lldp_cycle_interval,
                     raise_link_event_cycle_interval)