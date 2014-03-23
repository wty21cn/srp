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
本模块是Tor转发功能模块，可以通过监控ARP包来学习IP-MAC地址对，同时可以根据配置的静态ARP列表来对相应ARP请求进行应答。

本模块向控制台模块添加了arp对象，通过此对象可以查看和修改ARP Table

在启动本模块时可以通过以下命令添加静态ARP列表
  arp_func --<IP>=<MAC> --<IP>=<MAC>
如果MAC地址没有指定，则默认使用Switch的MAC地址
"""

from pox.core import core
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.addresses import IPAddr, EthAddr,parse_cidr,same_network
from pox.lib.recoco import Timer
from pox.lib.revent import Event,EventMixin
from pox.lib.util import dpid_to_str,str_to_dpid,str_to_bool

import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import time


#Global Var
log = core.getLogger()      #获得全局日志器
ARP_TIMEOUT = 60 * 4        #ARP列表项的超时时间(秒)
FLOW_IDLE_TIMEOUT = 60 * 3  #流表闲置超时时间(秒)
MAX_BUFFERED_PER_IP = 5     #Datapath为每个未知的目的IP地址缓存多少个报文
MAX_BUFFER_TIME = 5         #缓存报文的超时时间(秒)


class Entry (object):

    """
    The MAC is used to answer ARP replies.
    When timeout is older than ARP_TIMEOUT,
    Just flood the ARP request not to answer it
    """

    def __init__(self, mac, port=None, static=None, flood=None):
        self.timeout = time.time() + ARP_TIMEOUT
        self.static = False
        self.flood = True
        self.port = port
        if mac is True:
            # Means use switch's MAC, implies static/noflood
            self.mac = True
            self.static = True
            self.flood = False
        else:
            self.mac = EthAddr(mac)

        if static is not None:
            self.static = static
        if flood is not None:
            self.flood = flood

    def __eq__(self, other):
        if isinstance(other, Entry):
            return (self.static, self.mac) == (other.static, other.mac)
        else:
            return self.mac == other

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def is_expired(self):
        if self.static:
            return False
        return time.time() > self.timeout


class ARPTable (dict):

    def __repr__(self):
        o = []
        for k, e in self.iteritems():
            t = int(e.timeout - time.time())
            if t < 0:
                t = "X"
            else:
                t = str(t) + "s left"
            if e.static:
                t = "-"
            mac = e.mac
            port = e.port
            if mac is True:
                mac = "<Switch MAC>"
            o.append((k, "%-16s %-22s %-9s %3s" % (k, mac, port, t)))

        o.sort()
        o = [e[1] for e in o]
        o.insert(0, "----- ARP Table -----")
        if len(o) == 1:
            o.append("<< Empty >>")
        return "\n".join(o)

    def __setitem__(self, key, val):
        key = IPAddr(key)
        if not isinstance(val, Entry):
            val = Entry(val)
        dict.__setitem__(self, key, val)

    def __delitem__(self, key):
        key = IPAddr(key)
        dict.__delitem__(self, key)

    def set(self, key, value=True, static=True):
        if not isinstance(value, Entry):
            value = Entry(value, static=static)
        self[key] = value


class ARPTableSet(dict):

    def __repr__(self):
        repr = list()
        for dpid,table in self.items():
            repr.append("DPID:"+dpid)
            repr.append(table.__repr__()+"\n")
        return "\n".join(repr)


class SendARPRequest(Event):

    @property
    def dpid(self):
        return self.connection.dpid

    def __str__(self):
        return "Send ARPRequest to DPID-%s Port-%s: %s => %s" \
               % (self.dpid,self.outport,self.src_mac,self.src_ip)

    def __init__(self,con,src_ip=None,src_mac=None,dst_ip=None,dst_mac=None,outport=None,ofp=None,flood=False):
        super(SendARPRequest,self).__init__()
        self.connection = con
        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.dst_mac = dst_mac
        self.src_mac = src_mac
        self.outport = outport
        self.ofp = ofp
        self.flood = flood


class SendARPReply(Event):

    @property
    def dpid(self):
        return self.connection.dpid

    def __str__(self):
        return "Send ARPReply to DPID-%s Port-%s: %s => %s" \
               % (self.dpid,self.outport,self.src_mac,self.src_ip)

    def __init__(self,con,src_ip,src_mac,dst_ip,dst_mac,outport):
        super(SendARPReply,self).__init__()
        self.connection = con
        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.dst_mac = dst_mac
        self.src_mac = src_mac
        self.outport = outport


def _dpid_to_mac(dpid):
    # Should maybe look at internal port MAC instead?
    return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))


class ForwardingFunction (EventMixin):

    _eventMixin_events = set([SendARPRequest, SendARPReply])

    def __init__(self,timeout,no_flow,eat_packets,no_learn,*args,**kwargs):

        self.ARP_TIMEOUT = timeout
        self.install_flow = not no_flow
        self.eat_packets = eat_packets
        self.learn = not no_learn

        #buffer for packet stored in datapath
        self.ipv4_buffers = dict()
        self.arp_buffers = dict()


        # This timer handles expiring stuff
        self._expire_arp_table_timer = Timer(5, self._handle_arp_table_expiration,recurring=True)
        self._expire_ipv4_buffer_timer = Timer(5, self._handle_ipv4_buffer_expiration,recurring=True)
        self._expire_arp_buffer_timer = Timer(5, self._handle_arp_buffer_expiration,recurring=True)

        # Listen to dependencies
        core.addListeners(self)
        def _listen_to_dependencies():
            core.BaseUtil.addListeners(self)
        core.call_when_ready(_listen_to_dependencies, ('BaseUtil',))

        #Get SRPConfig
        def _get_config():
            log.debug('Config Module is loaded!')

            self.arp_table = ARPTableSet()
            for dpid in core.SRPConfig.tor_list:
                self.arp_table[dpid] = ARPTable()
                ip = IPAddr(parse_cidr(core.SRPConfig.get_tor_lan_addr(dpid))[0])
                self.arp_table[dpid][ip] = Entry(_dpid_to_mac(str_to_dpid(dpid)), static=True)
                for k, v in kwargs.iteritems():
                    self.arp_table[dpid][IPAddr(k)] = Entry(v, static=True)
            core.Interactive.variables['arp'] = self.arp_table
        core.call_when_ready(_get_config,('SRPConfig',))

    def _handle_arp_table_expiration(self):
        for dpid in core.SRPConfig.tor_list:
            for k, e in self.arp_table[dpid].items():
                if e.is_expired:
                    del self.arp_table[dpid][k]

    def _handle_arp_buffer_expiration(self):
        empty = []
        for k, v in self.arp_buffers.iteritems():
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
            del self.arp_buffers[k]

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
        return

    def _send_ipv4_buffer(self,dpid,dst_ip,mac,outport):
        if (dpid,dst_ip) in self.ipv4_buffers:
            log.debug("[%s] Send buffered ipv4 packets to %s",dpid,dst_ip)
            buffers = self.ipv4_buffers[(dpid,dst_ip)]
            del self.ipv4_buffers[(dpid,dst_ip)]
            for entry in buffers:
                msg = of.ofp_packet_out(buffer_id=entry[1],in_port=entry[2])
                msg.actions.append(of.ofp_action_dl_addr.set_dst(mac))
                msg.actions.append(of.ofp_action_output(port=outport))
                core.openflow.sendToDPID(str_to_dpid(dpid),msg)

    def _send_arp_buffer(self,dpid,dst_ip,mac,outport):
        if (dpid,dst_ip) in self.arp_buffers:
            log.debug("[%s] Send buffered arp packets to %s",dpid,dst_ip)
            buffers = self.arp_buffers[(dpid,dst_ip)]
            del self.arp_buffers[(dpid,dst_ip)]
            for entry in buffers:
                msg = of.ofp_packet_out(buffer_id=entry[1],in_port=entry[2])
                msg.actions.append(of.ofp_action_dl_addr.set_dst(mac))
                msg.actions.append(of.ofp_action_output(port=outport))
                core.openflow.sendToDPID(str_to_dpid(dpid),msg)

    def _handle_GoingUpEvent(self, event):
        core.openflow.addListeners(self)
        log.debug("Up...")

    def _handle_ConnectionUp(self, event):
        if self.install_flow:
            fm = of.ofp_flow_mod()
            fm.priority = 0x7000  # Pretty high
            fm.match.dl_type = ethernet.ARP_TYPE
            fm.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
            event.connection.send(fm)

    def _handle_ConnectionDown(self,event):
        dpid = dpid_to_str(event.connection.dpid)

        if dpid in core.SRPConfig.core_list:
            return

        log.debug("[%s] Clear non-static entry in ARPTable",dpid)
        for ip,entry in self.arp_table[dpid].items():
            if entry.static is not True:
                del self.arp_table[dpid][ip]
        log.debug("[%s] Clear ipv4 buffer",dpid)
        for k,entry in self.ipv4_buffers.iteritems():
            dpid_t,dst_ip = k
            if dpid == dpid_t:
                del self.ipv4_buffers[(dpid,dst_ip)]

        log.debug("[%s] Clear arp buffer",dpid)
        for k,entry in self.arp_buffers.iteritems():
            dpid_t,dst_ip = k
            if dpid == dpid_t:
                del self.arp_buffers[(dpid,dst_ip)]

    def _handle_ARPRequest(self,event):
        dpid = dpid_to_str(event.dpid)
        src_ip = event.arpp.protosrc
        src_mac = event.arpp.hwsrc
        dst_ip = event.arpp.protodst

        if dpid in core.SRPConfig.core_list:
            log.debug("[%s] Ignore ARPRequest Packet from Core Switch!",dpid)
            return

        if event.arpp.protodst in self.arp_table[dpid]:
            #如果本地存有此被请求表项，则交换机代替应答此ARPRequest
            dst_mac = self.arp_table[dpid][event.arpp.protodst].mac

            log.debug("[%s] Raise SendARPReply Event %s => %s",
                      dpid,dst_ip,src_ip)
            ev = SendARPReply(event.connection,dst_ip,dst_mac,src_ip,src_mac,event.inport)
            self.raiseEvent(ev)
        else:
            #如果本地没有存此请求表项，则交换机将此ARPRequest泛洪发送出去
            dst_mac = ETHER_BROADCAST
            log.debug("[%s] Raise SendARPRequest Event Flood out %s => %s",
                      dpid,src_ip,dst_ip)
            ev = SendARPRequest(event.connection,ofp=event.ofp,flood=True)
            self.raiseEvent(ev)

    def _handle_ARPReply(self,event):
        dpid = dpid_to_str(event.connection.dpid)
        src_ip = event.arpp.protosrc
        src_mac = event.arpp.hwsrc
        dst_ip = event.arpp.protodst
        dst_mac = event.arpp.hwdst
        inport = event.inport

        if dpid in core.SRPConfig.core_list:
            log.debug("[%s] Ignore ARPReply Packet from Core Switch!",dpid)
            return

        if same_network(dst_ip,core.SRPConfig.get_tor_lan_addr(dpid),32):
            self._send_arp_buffer(dpid,src_ip,src_mac,inport)
        else:
            if dst_ip in self.arp_table[dpid]:
                outport = self.arp_table[dpid][dst_ip].port
                log.debug("[%s] Raise SendARPReply Event %s => %s",
                      dpid,src_ip,dst_ip)
                ev = SendARPReply(event.connection,src_ip,src_mac,dst_ip,dst_mac,outport)
                self.raiseEvent(ev)
            else:
                #缓存ARP Reply报文，并广播ARPRequest报文请求目的IP地址的MAC地址
                log.debug("[%s] Buffer unsent arp packet point to %s",dpid,dst_ip)
                if (dpid,dst_ip) not in self.arp_buffers:
                    self.arp_buffers[(dpid,dst_ip)] = []
                buffers  = self.arp_buffers[(dpid,dst_ip)]
                entry = (time.time()+MAX_BUFFER_TIME,event.ofp.buffer_id,inport)
                buffers.append(entry)
                while len(buffers)>MAX_BUFFERED_PER_IP:
                    msg = of.ofp_packet_out(buffer_id=buffers[0][1],in_port=buffers[0][2])
                    event.connection.send(msg)
                    del buffers[0]

                #触发SendARPRequest事件，请求该ARP报文的目的IP地址对应的MAC地址
                src_ip = parse_cidr(core.SRPConfig.get_tor_lan_addr(dpid))[0]
                src_mac = _dpid_to_mac(event.connection.dpid)

                log.debug("[%s] Raise SendARPRequest Event %s => %s ",
                      dpid,src_ip,dst_ip)
                ev = SendARPRequest(event.connection,src_ip,src_mac,dst_ip,ETHER_BROADCAST,flood=True)
                self.raiseEvent(ev)

    def _handle_NewIpMacPortPair(self,event):
        ip = event.src_ip
        mac = event.src_mac
        port = event.inport
        dpid = dpid_to_str(event.connection.dpid)

        if dpid in core.SRPConfig.core_list:
            log.debug("[%s] Ignore New Ip Mac Port Pair from Core Switch!",dpid)
            return

        if not same_network(ip,core.SRPConfig.get_tor_lan_addr(dpid)):
            log.debug("[%s] Ignore New IP Mac Port Pair with ip not belong to the DPID!",dpid)
            return

        if ip in self.arp_table[dpid]:
            del self.arp_table[dpid][ip]
        self.arp_table[dpid][ip] = Entry(mac,port)

        #发送之前缓存的buffer中的报文
        self._send_ipv4_buffer(dpid,ip,mac,port)

    def _handle_IPv4In(self,event):
        dst_ip = event.ipv4p.dstip
        dpid = dpid_to_str(event.connection.dpid)
        inport = event.inport

        if dpid in core.SRPConfig.core_list:
            return

        if same_network(dst_ip,core.SRPConfig.get_tor_lan_addr(dpid)):
            #判断目的网段是否在对应DPID连接的网段中
            if dst_ip in self.arp_table[dpid]:
                #判断之前是否已经获得目的IP地址的MAC地址
                table = self.arp_table[dpid][dst_ip]

                log.debug("[%s] Send out the ipv4 packet: %s =>%s",dpid,event.ipv4p.srcip,dst_ip)
                msg = of.ofp_packet_out(buffer_id = event.ofp.buffer_id, in_port = inport)
                msg.actions.append(of.ofp_action_dl_addr.set_dst(table.mac))
                msg.actions.append(of.ofp_action_output(port = table.port))
                event.connection.send(msg)

                log.debug("[%s] Set up the Flow for destination: %s",dpid,dst_ip)
                actions = list()
                actions.append(of.ofp_action_dl_addr.set_dst(table.mac))
                actions.append(of.ofp_action_output(port = table.port))
                match = of.ofp_match()
                match.dl_type = pkt.ethernet.IP_TYPE
                match.nw_dst = dst_ip
                msg = of.ofp_flow_mod(command = of.OFPFC_MODIFY,
                                      actions = actions,
                                      match = match,
                                      idle_timeout = FLOW_IDLE_TIMEOUT,
                                      hard_timeout = of.OFP_FLOW_PERMANENT)
                event.connection.send(msg)
            else:
                #缓存IPv4报文，并广播ARPRequest报文请求目的IP地址的MAC地址
                log.debug("[%s] Buffer unsent IPv4 packet point to %s",dpid,dst_ip)
                if (dpid,dst_ip) not in self.ipv4_buffers:
                    self.ipv4_buffers[(dpid,dst_ip)] = []
                buffers  = self.ipv4_buffers[(dpid,dst_ip)]
                entry = (time.time()+MAX_BUFFER_TIME,event.ofp.buffer_id,inport)
                buffers.append(entry)
                while len(buffers)>MAX_BUFFERED_PER_IP:
                    msg = of.ofp_packet_out(buffer_id=buffers[0][1],in_port=buffers[0][2])
                    event.connection.send(msg)
                    del buffers[0]

                #触发SendARPRequest事件，请求该IPv4报文的目的IP地址对应的MAC地址
                src_ip = parse_cidr(core.SRPConfig.get_tor_lan_addr(dpid))[0]
                src_mac = _dpid_to_mac(event.connection.dpid)

                log.debug("[%s] Raise SendARPRequest Event %s | %s => %s | %s",
                      dpid,src_ip,src_mac,dst_ip,ETHER_BROADCAST)
                ev = SendARPRequest(event.connection,src_ip,src_mac,dst_ip,ETHER_BROADCAST,flood=True)
                self.raiseEvent(ev)
        else:
            return


def launch(timeout=ARP_TIMEOUT,
           no_flow=True,
           eat_packets=True,
           no_learn=False,
           *args,**kwargs):

    core.registerNew(ForwardingFunction,
                     int(timeout),
                     str_to_bool(no_flow),
                     str_to_bool(eat_packets),
                     str_to_bool(no_learn),
                     *args,**kwargs)
