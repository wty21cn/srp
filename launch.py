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
启动模块，用于启动本项目所需的各个功能模块，并且设定规范化的log格式
"""


def launch(tor_num=20,core_num=6,**kw):
    import pox.log.color
    pox.log.color.launch()

    import pox.log
    pox.log.launch(format="[@@@bold@@@level%(name)-23s@@@reset] " +
                          "@@@bold%(message)s@@@normal")
    import pox.log.level
    pox.log.level.launch(**kw)

    import srp_config
    srp_config.launch(tor_num,core_num)

    import base_util
    base_util.launch()

    import forwarding_func
    forwarding_func.launch()

    import lldp_util
    lldp_util.launch()

    import srp_func
    srp_func.launch()


