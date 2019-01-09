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
            connection=SocketConnection("127.0.0.1", 502, proto='tcp')))

    s_initialize("header")

    s_word(0xe8)    # 2 byte: transaction id
    s_word(0x00)    # 2 byte: protocol id

    s_word(0x05)    # 2 byte: len

    s_byte(0x01)    # 1 byte: unit id

    s_byte(0x03)    # 1 byte: func code
    s_byte(0x02)    # 2 byte: word count

    s_word(0x41c8)  # 2 byte: register

    print s_get().render()

    session.connect(s_get("header"))
    session.fuzz()


if __name__ == "__main__":
    main()
