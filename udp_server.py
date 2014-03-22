#!/usr/bin/python

import socket
import datetime
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("",9154))
if len(sys.argv)==1:
    verbose = False
else:
    verbose = True if sys.argv[1]=="v" else False
count = 0
pre_data = 0
while True:
    start = datetime.datetime.now()
    data, addr = s.recvfrom(1024)
    data = int(data)
    end = datetime.datetime.now()
    period = end - start
    if pre_data == data-1:
        if verbose:
            print "(",data,",",period,")",
            count += 1
            if count == 3:
                print ""
                count = 0
    else:
        if count == 0:
            if pre_data !=0:
                if verbose:
                    print "!!!!(",data,",",period,")!!!!\n"
                else:
                    print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                    print "  Previous Received Pkt Seq:",pre_data
                    print "  Last Received Pkt Seq    :",data
                    print "  Lost Pkt Num             :",data-pre_data
                    print "  Link Down Time           :",period
                    print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                    print "\n"

        else:
            print "\n\n!!!!(",data,",",period,")!!!!\n"
            count = 0
    pre_data = data
    pre_period = period