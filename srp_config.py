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
本模块为SRP配置模块，向Core注册为实例SRPConfig

配置的参数为：
tor_list Set--配置哪些DPID为Tor Switch
tor_addr_config Dict--配置各个Tor Switch连接的LAN网段是多少
"""


from pox.core import core


# Create a logger for this component
log = core.getLogger()


class SRPConfig(object):

    def get_tor_lan_addr(self,dpid):
        return self.tor_addr_config[dpid]

    def __init__(self,sn):
        self.tor_list = set()
        self.tor_addr_config= dict()
        for s in range(sn):
            dpid = "00-00-%0.2x-00-00-00" % (s+1)
            ip = "192.168.%i.254/24" % (s+1)
            self.tor_list.add(dpid)
            self.tor_addr_config[dpid] = ip

def launch(sn):

   core.registerNew(SRPConfig,int(sn))
