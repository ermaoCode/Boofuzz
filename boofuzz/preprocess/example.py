#!/usr/bin/env python
# Designed for use with boofuzz v0.0.8
from boofuzz import *
import json
import sys
import argparse
import traceback
import types

def addPrimitive(primitive):
    if primitive["type"] == "string":
        s_string(primitive["value"])
    elif primitive["type"] == "delim":
        s_delim(primitive["value"])
    elif primitive["type"] == "static":
        s_static(primitive["value"])

def get_priAttr_by_name(primitive, name):
    for primitive_attribute in primitive:
        if primitive_attribute["name"] == name:
            return primitive_attribute
    print "primitive-type '%s' not found "% (name)
    sys.exit()

def addStatus(status):
    s_initialize(status["status_name"])
    for block in status["blocks"]:
        if s_block_start(block["block_name"]):
            for primitive in block["block_item"]:
                attr = get_priAttr_by_name(primitive["primitive"], "primitive-type")

                if attr["default_value"] == "static":
                    s_static(get_priAttr_by_name(primitive["primitive"], "primitive-value")["default_value"])
                elif attr["default_value"] == "delim":
                    s_delim(get_priAttr_by_name(primitive["primitive"], "primitive-value")["default_value"],
                            fuzzable=(get_priAttr_by_name(primitive["primitive"], "fuzzable")["default_value"] == "True"))
                elif attr["default_value"] == "string":
                    s_string(get_priAttr_by_name(primitive["primitive"], "primitive-value")["default_value"],
                             fuzzable=(get_priAttr_by_name(primitive["primitive"], "fuzzable")["default_value"] == "True"),
                             max_len=get_priAttr_by_name(primitive["primitive"], "max-length")["default_value"])

        s_block_end()

def byteify(input):
    if isinstance(input, dict):
        return {byteify(key):byteify(value) for key,value in input.iteritems()}
    elif isinstance(input, list):
        return [byteify(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input

def main():
    parser = argparse.ArgumentParser(description='A amazing fuzzing tools.')
    parser.add_argument('--script', '-s', dest="script", help = 'fuzzingScript.json path')
    parser.add_argument('--logtxtpath', '-t', dest="logtxt", help = 'log.txt file path')
    # parser.add_argument('--loghtmlpath', '-x', dest="loghtml", help = 'log.html file path')
    parser.add_argument('--tmplogpath', '-l', dest="tmplog", help = 'tmp log file')
    args = parser.parse_args()

    y = {}
    with open(args.script) as f:
        y = json.load(f)

    # transmit unicode to str
    y = byteify(y)

    # fuzz_loggers = [fuzz_logger_text.FuzzLoggerText()]
    fuzz_loggers = [fuzz_logger_html_table.FuzzLoggerHtml()]




    if (args.tmplog):
        tmplog = open(args.tmplog, "w+")
        fuzz_loggers.append(fuzz_logger_text.FuzzLoggerText(file_handle=tmplog))

    if (args.logtxt):
        logfile = open(args.logtxt, "w+")
        fuzz_loggers.append(fuzz_logger_text.FuzzLoggerText(file_handle=logfile))

    # if (args.loghtml):
    #     # htmlfile = open(args.loghtml, "w+")
    #     fuzz_loggers.append(fuzz_logger_html.FuzzLoggerHtml())

    try:
        port = y["test"]["session"]["target"]["port"]
        if type(port) is types.StringType:
            port = int(port)
        session = Session(
            target=Target(
                connection=SocketConnection(y["test"]["session"]["target"]["ip"],
                                            port,
                                            proto=y["test"]["session"]["target"]["protocol"],
                                            bind=bind)),
            fuzz_loggers = fuzz_loggers)
        pre_status = ""

        for status in y["test"]["status"]:
            addStatus(status)

        for status in y["test"]["status"]:
            if pre_status == "":
                session.connect(s_get(status["status_name"]))
                pre_status = status["status_name"]
            else:
                session.connect(pre_status, s_get(status["status_name"]))
                pre_status = status["status_name"]

        session.fuzz()
    except Exception as e:
        print "error: " + str(e)
        traceback.print_exc()

if __name__ == "__main__":
    main()
