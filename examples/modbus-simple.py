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

    s_word(0x01)
    s_word(0x00)

    s_word(0x05)  # len

    s_byte(0x01)  # unit id

    s_byte(0x03)  # func code
    s_byte(0x02)  # word count

    s_word(0x12312)

    print s_get().render()

    session.connect(s_get("header"))
    session.fuzz()


if __name__ == "__main__":
    main()
