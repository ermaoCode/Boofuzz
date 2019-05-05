#!/usr/bin/env python
# Designed for use with boofuzz v0.0.8
import sys
sys.path.append("..")
from boofuzz import *
import datetime
import psutil
import os

def main():
    """
    This example is a very simple FTP fuzzer. It uses no process monitory
    (procmon) and assumes that the FTP server is already running.
    """
    session = Session(
        target=Target(
            connection=SocketConnection("192.168.1.159", 80, proto='tcp')))

    s_initialize("user")
    s_string("USER")
    s_delim(" ")
    s_string("anonymous")
    s_static("\r\n")

    s_bit_field(0, width=24, full_range=True)

    s_initialize("pass")
    s_string("PASS")
    s_delim(" ")
    s_string("james")
    s_static("\r\n")

    s_initialize("stor")
    s_string("STOR")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")

    s_initialize("retr")
    s_string("RETR")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")

    session.connect(s_get("user"))
    session.connect(s_get("user"), s_get("pass"))
    session.connect(s_get("pass"), s_get("stor"))
    session.connect(s_get("pass"), s_get("retr"))

    print session.num_mutations()

    print "memory usage: ", psutil.Process(os.getpid()).memory_info().rss


if __name__ == "__main__":
    now = datetime.datetime.now()
    main()
    end = datetime.datetime.now()
    print ("Running " + str(end-now))
