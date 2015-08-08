# coding:utf-8

"""
本模块为基本工具模块，作为整个项目中转发功能的事件起点，
响应PacketIn事件，并根据事件特点分别触发ARPRequst、ARPReply、Ipv4In和NewIpMacPortPairt事件
也可监听其他功能模块发出的SendARPRequest和SendARPReply事件，并向Datapath发出附带相应报文的PacketOut消息
"""

from pox.core import core
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.util import dpid_to_str, str_to_bool
from pox.lib.revent import EventHalt, Event, EventMixin

import pox.openflow.libopenflow_01 as of


#Global Var
log = core.getLogger()


class ARPRequest (Event):

    @property
    def dpid(self):
        return self.connection.dpid

    def __str__(self):
        return "ARPRequest for %s on %s" \
               % (self.ip, dpid_to_str(self.dpid))

    def __init__(self, event, arpp, reply_from, eat_packet, inport):
        super(ARPRequest, self).__init__()
        self.ofp = event.ofp
        self.connection = event.connection
        self.arpp = arpp  # ARP packet
        self.reply_from = reply_from  # MAC
        self.eat_packet = eat_packet
        self.inport = inport
        self.reply = None  # Set to desired EthAddr


class ARPReply (Event):

    @property
    def dpid(self):
        return self.connection.dpid

    def __str__(self):
        return "ARPReply for %s on %s" \
               % (self.arpp.protodst,dpid_to_str(self.dpid))

    def __init__(self, event, arpp, eat_packet, inport):
        super(ARPReply, self).__init__()
        self.ofp = event.ofp
        self.connection = event.connection
        self.arpp = arpp
        self.eat_packet = eat_packet
        self.inport = inport


class NewIpMacPortPair(Event):

    @property
    def dpid(self):
        return self.connection.dpid

    def __str__(self):
        return "Add New DPID-%s ARPTable Entry: %s | %s | %s " \
               % (self.dpid,self.inport,self.src_mac,self.src_ip)

    def __init__(self,con,src_ip,src_mac,inport):
        super(NewIpMacPortPair,self).__init__()
        self.connection = con
        self.src_ip = src_ip
        self.src_mac = src_mac
        self.inport = inport


class IPv4In(Event):

    @property
    def dpid(self):
        return self.connection.dpid

    def __str__(self):
        return "New IPv4 Packet is arrived at %s destinate at %s" \
                % (self.dpid,self.ipv4p.dstip)

    def __init__(self,event,ipv4p,eat_packet,inport):
        super(IPv4In,self).__init__()
        self.ofp = event.ofp
        self.connection = event.connection
        self.ipv4p = ipv4p
        self.eat_packet = eat_packet
        self.inport = inport


class BaseUtil (EventMixin):
    _eventMixin_events = set([ARPRequest, ARPReply, NewIpMacPortPair, IPv4In])

    def __init__(self, no_flow, eat_packets,use_port_mac):
        self.install_flow = not no_flow
        self.eat_packets = eat_packets
        self.use_port_mac = use_port_mac

        #Listen to dependencies
        core.addListeners(self)
        def _listen_to_dependencies():
            core.ForwardingFunction.addListeners(self)
        core.call_when_ready(_listen_to_dependencies, ('ForwardingFunction',))

    def _handle_SendARPRequest(self,event):
        dpid = dpid_to_str(event.connection.dpid)
        if event.ofp is not None:
            log.debug("[%s] Handle SendARPRequest Event using ofp!",dpid)
            msg = of.ofp_packet_out()
            msg.data = event.ofp
        else:
            log.debug("[%s] Handle SendARPRequest Event! %s => %s",dpid,event.src_ip,event.dst_ip)
            r = arp()
            r.opcode = r.REQUEST
            r.hwdst = EthAddr(event.dst_mac)
            r.protodst = IPAddr(event.dst_ip)
            r.hwsrc = EthAddr(event.src_mac)
            r.protosrc = IPAddr(event.src_ip)
            e = ethernet(type=ethernet.ARP_TYPE, src=EthAddr(r.hwsrc), dst=EthAddr(r.hwdst))
            e.payload = r
            msg = of.ofp_packet_out()
            msg.data = e.pack()
        if event.flood is True:
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        else:
            msg.actions.append(of.ofp_action_output(port=event.outport))
            msg.in_port = of.OFPP_NONE
        event.connection.send(msg)

    def _handle_SendARPReply(self,event):
        dpid = dpid_to_str(event.connection.dpid)
        log.debug("[%s] Handle SendARPReply Event! %s => %s",dpid,event.src_ip,event.dst_ip)

        r = arp()
        r.opcode = r.REPLY
        r.hwdst = EthAddr(event.dst_mac)
        r.protodst = IPAddr(event.dst_ip)
        r.hwsrc = EthAddr(event.src_mac)
        r.protosrc = IPAddr(event.src_ip)
        e = ethernet(type=ethernet.ARP_TYPE, src=EthAddr(r.hwsrc), dst=EthAddr(r.hwdst))
        e.payload = r
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=event.outport))
        msg.in_port = of.OFPP_NONE
        event.connection.send(msg)

    def _handle_GoingUpEvent(self, event):
        core.openflow.addListeners(self,priority=100)
        log.debug("Up...")

    def _handle_ConnectionUp(self, event):
        if self.install_flow:
            fm = of.ofp_flow_mod()
            fm.priority = 0x7000   #Pretty High
            fm.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
            fm.match.dl_type = ethernet.ARP_TYPE
            event.connection.send(fm)
            fm.match.dl_type = ethernet.IP_TYPE
            event.connection.send(fm)

    def _handle_PacketIn(self, event):
        dpid = dpid_to_str(event.connection.dpid)
        inport = event.port
        packet = event.parsed

        if not packet.parsed:
            log.warning("%s %i ignoring unparsed packet", dpid, inport)
            return

        if isinstance(packet.next,arp):
            p = packet.find('arp')

            if p.prototype != arp.PROTO_TYPE_IP:
                return

            if p.hwtype != arp.HW_TYPE_ETHERNET:
                return

            #触发NewIpMacPortPair事件
            log.debug("[%s] Raise NewIpMacPortPair Event: %s | %s | %s",
                      dpid,inport,p.hwsrc,p.protosrc)

            ev = NewIpMacPortPair(event.connection,p.protosrc,p.hwsrc,inport)
            self.raiseEvent(ev)

            if p.opcode == arp.REQUEST:
                log.debug("[%s] Receive An ARP request %s => %s",
                          dpid,p.protosrc,p.protodst)

                if self.use_port_mac:
                    src_mac = event.connection.ports[inport].hw_addr
                else:
                    src_mac = event.connection.eth_addr

                #触发ARPRequest事件
                ev = ARPRequest(event,p,src_mac,self.eat_packets,inport)
                self.raiseEvent(ev)

                return EventHalt if ev.eat_packet else None

            elif p.opcode == arp.REPLY:
                log.debug("[%s] Receive An ARP reply %s => %s",
                          dpid,p.protosrc, p.protodst)

                #触发ARPRequest事件
                ev = ARPReply(event, p, self.eat_packets, inport)
                self.raiseEvent(ev)

                return EventHalt if ev.eat_packet else None

        elif isinstance(packet.next,ipv4):
            p = packet.find('ipv4')

            #触发NewIpMacPortPair事件
            log.debug("[%s] Raise NewIpMacPortPair Event: %s | %s | %s",
                      dpid,inport,packet.src,p.srcip)

            ev = NewIpMacPortPair(event.connection,p.srcip,packet.src,inport)
            self.raiseEvent(ev)

            log.debug("[%s] Receive An IPv4 Packet %s => %s",
                      dpid,p.srcip,p.dstip)

            #触发IPv4In事件
            ev = IPv4In(event,p,self.eat_packets,inport)
            self.raiseEvent(ev)

            return EventHalt if ev.eat_packet else None


def launch(no_flow=True,
           eat_packets=True,
           use_port_mac=False):

    core.registerNew(BaseUtil,
                     str_to_bool(no_flow),
                     str_to_bool(eat_packets),
                     str_to_bool(use_port_mac))
