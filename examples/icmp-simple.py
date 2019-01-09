#!/usr/bin/env python
# Designed for use with boofuzz v0.0.8
from boofuzz import *
import socket
def main():
    """
    This example is a very icmp fuzzer.
    """
    session = Session(
        target=Target(
            connection=SocketConnection("127.0.0.1", 0, proto='ip', ip_header_proto_num=socket.IPPROTO_ICMP)))

    s_initialize("all")
    # construct icmp package

    if s_block_start("icmp"):
        s_byte(0x08, fuzzable=False)            # 1 byte: echo reqest icmp_type
        s_byte(0x00, fuzzable=False)            # 1 byte icmp_code

        s_checksum( "icmp", algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # 2 byte icmp_checksum

        s_word(0x0c36, endian=BIG_ENDIAN, fuzzable=False)          # 2 byte: id icmp_id
        s_word(0x0, endian=BIG_ENDIAN, fuzzable=False)             # 2 byte:seq number
        s_bit_field(0x0, 8*8, endian=BIG_ENDIAN, fuzzable=False)   # 8 byte : timestamp

        s_string("hello icmp")

    s_block_end()



    session.connect(s_get("all"))
    session.fuzz()


if __name__ == "__main__":
    main()
