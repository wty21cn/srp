#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel,info
import sys
import copy

def create_test_topo(hn=3,tor_num=2,core_num=2):
    """
    Topology Fort Testing
    """
    #Var
    lan_prefix =["192.168.%d." % (i+1) for i in range(tor_num)]
    netmask = "/24"


    info("--- Creating Mininet\n")
    net = Mininet(controller=RemoteController)
    info(net)
    info("\n--- Creating Mininet Finished\n\n\n")

    info("--- Adding Remote Controller\n")
    c0 = net.addController("c0",controller=RemoteController,ip="192.168.97.1",port=6633)
    info(c0)
    info("\n--- Adding Remote Controller Finished\n\n\n")

    info("--- Adding Openflow Switches\n")
    tswitches = []
    info('Add Tor Switch: ')
    for i in range(tor_num):
        name = "ts%d" % (i+1)
        dpid = "00000000%0.2x000000" % (i+1)
        tswitches.append(net.addSwitch(name,dpid=dpid ))
        info(tswitches[i],' ')
    info("\n")
    cswitches = []
    info('Add Core Switch: ')
    for i in range(core_num):
        name = "cs%d" % (i+1)
        dpid = "00001000%0.2x000000" % (i+1)
        cswitches.append(net.addSwitch(name,dpid=dpid))
        info(cswitches[i],' ')
    info("\n--- Adding Openflow Switches Finished\n\n\n")

    info("--- Adding Hosts\n")
    hosts = []
    for i in range(tor_num):
        hosts.append([])
        for j in range (hn):
            ip = lan_prefix[i]+"%d"%(j+1)+netmask
            mac = "00:00:%0.2x:00:00:%0.2x"% (i+1,j+1)
            hostname = "h%d_%d" % (j+1,i+1)
            hosts[i].append(net.addHost(hostname,ip=ip,mac=mac))
            info(hosts[i][j],' ')
    info("\n--- Adding Hosts Finished\n\n\n")



    info("--- Adding Links\n")
    #Adding links between switch and host
    for i in range(tor_num):
        for j in range(hn):
            net.addLink(hosts[i][j],tswitches[i])
            info("(",hosts[i][j],"->",tswitches[i],")")
    #Adding links between switch and switch
    for t in range(tor_num):
        for c in range(core_num):
            net.addLink(tswitches[t],cswitches[c])
            info("(",tswitches[t],"->",cswitches[c],")")
    info("\n--- Adding Links Finished\n\n\n")

    info("--- Starting Network\n")
    net.start()

    info("*** Setting Hosts' Configuration\n")
    for i in range(tor_num):
        for j in range (hn):
            gateway = lan_prefix[i]+"254"
            hostname = "h%d_%d" % (j+1,i+1)
            cmd = "ip route add default dev %s-eth0 via %s" % (hostname,gateway)
            hosts[i][j].cmd(cmd)
            info(hosts[i][j],":",cmd,"\n")

    info("*** Setting Switches' Configuration\n")

    info("--- Starting Network Finished\n\n\n")


    info("--- Running CLI\n\n")
    CLI(net)
    info("--- Running CLI Finished\n\n\n")


    info("--- Stopping Network\n\n")
    net.stop()
    info("--- Network Stopped\n\n\n")

if __name__ == "__main__":
    setLogLevel("info")
    argv = copy.deepcopy(sys.argv)
    argv.pop(0)
    argv = [int(arg) for arg in argv]
    apply(create_test_topo,argv)



