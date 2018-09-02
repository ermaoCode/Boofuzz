#!/usr/bin/env python
# Designed for use with boofuzz v0.0.8
from boofuzz import *


def main():
    """
    This example is a very simple FTP fuzzer. It uses no process monitory
    (procmon) and assumes that the FTP server is already running.
    """
    session = Session(
        target=Target(
            connection=SocketConnection("7.7.7.7", 666, proto='raw-tcp')))

    s_initialize("all")
    # construct TCP header
    s_word(0x51)   # src port
    s_word(0x50)   # dst port

    s_dword(0x1)   # seq number
    s_dword(0x1)   # ack number

    tcp_data_offset = 5
    s_bit_field(tcp_data_offset, 4)  # header length

    s_bit_field(0x002, 12)  # flags  0000 0000 0010   syn

    s_word(3000)  # window size

    # TODO checksum
    s_word(0)

    s_word(0)     # urgent pointer

    s_string("hello world")



    session.connect(s_get("all"))
    session.fuzz()


if __name__ == "__main__":
    main()
