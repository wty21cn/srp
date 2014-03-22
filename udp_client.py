#!/usr/bin/python

import socket
import time
import sys

prefix = "192.168."
hn = sys.argv[1]
sn = sys.argv[2]
sleep_time = float(sys.argv[3])
addr = (prefix+"%s.%s" % (sn,hn),9154)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

i = 1
while True:
    i += 1
    data = "%i" % i
    s.sendto(data,addr)
    time.sleep(sleep_time)