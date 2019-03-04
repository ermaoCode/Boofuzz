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
            connection=SocketConnection("192.168.1.186", 502, proto='tcp')))

    s_initialize("header")

    s_word(0x00, fuzzable=False)    # 2 byte: transaction id
    s_word(0x00, fuzzable=False)    # 2 byte: protocol id

    s_word(0x06, endian=">", fuzzable=False)    # 2 byte: len

    s_byte(0x01, fuzzable=False)    # 1 byte: unit id

    s_byte(0x03, fuzzable=False)    # 1 byte: func code
    s_word(0x00, fuzzable=False)    # 2 byte: word count

    s_word(10, fuzzable=True)  # 2 byte: register

    # print s_get().render()

    session.connect(s_get("header"))
    session.fuzz()


if __name__ == "__main__":
    main()
