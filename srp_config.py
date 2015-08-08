# coding:utf-8


"""
本模块为SRP配置模块，向Core注册为实例SRPConfig

配置的参数为：
tor_list Set--配置哪些DPID为Tor Switch
tor_addr_config Dict--配置各个Tor Switch连接的LAN网段是多少
"""


from pox.core import core


#Global Var
log = core.getLogger()


class SRPConfig(object):

    def get_tor_lan_addr(self,dpid):
        return self.tor_addr_config[dpid]

    def __init__(self,tor_num,core_num):
        core.addListeners(self)
        self.tor_list = set()
        self.tor_addr_config= dict()
        self.core_list = set()
        for s in range(tor_num):
            dpid = "00-00-%0.2x-00-00-00" % (s+1)
            ip = "192.168.%i.254/24" % (s+1)
            self.tor_list.add(dpid)
            self.tor_addr_config[dpid] = ip
        for s in range(core_num):
            dpid = "10-00-%0.2x-00-00-00" % (s+1)
            self.core_list.add(dpid)

    def _handle_GoingUpEvent(self, event):
        core.openflow.addListeners(self)
        log.debug("Up...")

def launch(tor_num,core_num):

   core.registerNew(SRPConfig,int(tor_num),int(core_num))
