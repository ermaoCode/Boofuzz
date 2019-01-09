#!/usr/bin/env python
# Designed for use with boofuzz v0.0.8
from boofuzz import *


def hex_str(s):
    """
    Returns a hex-formatted string based on s.

    Args:
        s (bytes): Some string.

    Returns:
        str: Hex-formatted string representing s.
    """
    return ' '.join("{:02x}".format(b) for b in bytearray(s))



def hex_to_hexstr(input_bytes):
    """
    Render input_bytes as ASCII-encoded hex bytes, followed by a best effort
    utf-8 rendering.

    Args:
        input_bytes (bytes): Arbitrary bytes

    Returns:
        str: Printable string
    """
    return hex_str(input_bytes) + " " + repr(input_bytes)

def main():
    """
    This example is a very simple FTP fuzzer. It uses no process monitory
    (procmon) and assumes that the FTP server is already running.
    """
    session = Session(
        target=Target(
            connection=SocketConnection("127.0.0.1", 6666, proto='tcp')))

    s_initialize("retr")
    # s_string("RETR")
    # s_delim(" ")
    # s_string("AAAA")
    # s_static("\r\n")

    if s_block_start("blo1"):
        s_string("hello")


    s_block_end()
    s_static("\x00\x00\x00\x00")
    s_checksum("blo1", algorithm='ipv4',endian=BIG_ENDIAN)
    s_static("\x00\x00\x00\x00")

    if s_block_start("blo2"):
        s_checksum("blo2", algorithm='ipv4',endian=BIG_ENDIAN)
        s_string("hello")

    s_block_end()

    res = s_get().render()
    print res

    print "---------------------------------- "
    print s_hex_dump(res)


    # session.connect(s_get("user"))
    # session.connect(s_get("user"), s_get("pass"))
    # session.connect(s_get("pass"), s_get("stor"))
    # session.connect(s_get("pass"), s_get("retr"))
    #
    # session.fuzz()


if __name__ == "__main__":
    main()
