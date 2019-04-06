# Designed for use with boofuzz v0.0.8
import sys
sys.path.append("..")
from boofuzz import *


def main():
    session = Session(
        target=Target(
            connection=SocketConnection("192.168.1.186", 7000, proto='tcp', ip_header_proto_num=6)))

    s_initialize("header")

    s_static("\u0001")
    s_static("\u0002")
    s_static("\u0003")
    s_static("\u0004\x05\x06\x07\x08")
    s_string("hello")

    session.connect(s_get("header"))
    session.fuzz()


if __name__ == "__main__":
    main()
