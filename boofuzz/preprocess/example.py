#!/usr/bin/env python
# Designed for use with boofuzz v0.0.8
from boofuzz import *
import yaml

def addPrimitive(primitive):
    if primitive["type"] == "string":
        s_string(primitive["value"])
    elif primitive["type"] == "delim":
        s_delim(primitive["value"])
    elif primitive["type"] == "static":
        s_static(primitive["value"])

def main():
    f = open("example.yaml")
    # print f.read()
    y = yaml.load(f.read())
    # print y
    try:
        session = Session(
            target=Target(
                connection=SocketConnection(y["session"]["targetconnection"]["ip"],
                                            y["session"]["targetconnection"]["port"],
                                            proto=y["session"]["targetconnection"]["protocol"])))
        pre_status = ""

        for status in y["status"]:
            s_initialize(status["statusname"])
            for primitive in status["primitives"]:
                addPrimitive(primitive)

            if pre_status == "":
                session.connect(s_get(status["statusname"]))
                pre_status = status["statusname"]
            else:
                session.connect(pre_status, s_get(status["statusname"]))
                pre_status = status["statusname"]

        session.fuzz()
    except Exception as e:
        print "error: "+ str(e)

if __name__ == "__main__":
    main()
