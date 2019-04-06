#!/usr/bin/env python
# Designed for use with boofuzz v0.0.8
from boofuzz import *


def main():
    session = Session(
        target=Target(
            connection=SocketConnection("192.168.1.186", 502, proto='tcp')))

    s_initialize("header")
    if s_block_start("b0"):
        if s_block_start("b1"):
            s_string("a"*31)    # 2 byte: protocol id
            s_size("b1", length=4)

        s_block_end()
    s_block_end()

    # print s_get().render()

    session.connect(s_get("header"))
    session.fuzz()


if __name__ == "__main__":
    main()
