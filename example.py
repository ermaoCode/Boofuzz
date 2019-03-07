#!/usr/bin/env python
# Designed for use with boofuzz v0.0.8
from boofuzz import *
import json
import sys
import argparse
import traceback


def get_priAttr_by_name(primitive, name):
    for primitive_attribute in primitive:
        if primitive_attribute["name"] == name:
            return primitive_attribute
    print "primitive-type '%s' not found "% (name)
    sys.exit()


def add_primitive(primitive):
    # get the "primitive-type" element of this primitive
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
    elif attr["default_value"] == "byte":
        # s_string(get_priAttr_by_name(primitive["primitive"], "primitive-value")["default_value"],
        #         size=get_priAttr_by_name(primitive["primitive"], "width")["default_value"])
        s_bit_field(get_priAttr_by_name(primitive["primitive"], "primitive-value")["default_value"],
                    width=8*get_priAttr_by_name(primitive["primitive"], "width")["default_value"],
                    full_range=(get_priAttr_by_name(primitive["primitive"], "fuzzing-type")["default_value"]=="exhaustive"))
    elif attr["default_value"] == "random_data":
        s_random(get_priAttr_by_name(primitive["primitive"], "primitive-value")["default_value"],
                 min_length=get_priAttr_by_name(primitive["primitive"], "min-width")["default_value"],
                 max_length=get_priAttr_by_name(primitive["primitive"], "max-width")["default_value"],
                 num_mutations=get_priAttr_by_name(primitive["primitive"], "max-mutation")["default_value"])
    elif attr["default_value"] == "checksum_field":
        s_checksum(get_priAttr_by_name(primitive["primitive"], "target-block")["default_value"],
                   algorithm=get_priAttr_by_name(primitive["primitive"], "checksum-algorithm")["default_value"],
                   endian=">")
    elif attr["default_value"] == "length_field":
        s_size(get_priAttr_by_name(primitive["primitive"], "target-block")["default_value"],
               # offset=get_priAttr_by_name(primitive["primitive"], "offset")["default_value"],  # use block name to verify
               length=get_priAttr_by_name(primitive["primitive"], "width")["default_value"],
               endian=">")


def add_status(status):
    s_initialize(status["status_name"])
    if s_block_start("total"):
        for block in status["blocks"]:
            if s_block_start(block["block_name"]):
                for primitive in block["block_item"]:
                    add_primitive(primitive)
            s_block_end()
    s_block_end()

# Recursively transmit object to utf-8
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
    parser.add_argument('script', help='FuzzingScript.json path')
    parser.add_argument('--txtlog', help='Text format logging file path, used for displaying and searching detail')
    parser.add_argument('--jsonlog', help='Json format logging file path, used for generation HTML page')
    parser.add_argument('--bindip', help='Ip address for sending')
    parser.add_argument("--onlygenerate", help="A flag, if you turn it on, it will only generate test cases " +
                                               "rather then run the whole test", action="store_true")
    args = parser.parse_args()

    bind = None
    if (args.bindip and args.bindip != "0"):
        bind = (args.bindip, 0)

    only_generate = 0
    if args.onlygenerate:
        only_generate = 1

    # load json script
    y = {}
    with open(args.script) as f:
        y = json.load(f)
    # transmit unicode to str
    y = byteify(y)

    # init loggers
    # txt logger
    fuzz_loggers = []
    if args.txtlog:
        logfile = open(args.txtlog, "w+")

        # common format
        fuzz_loggers.append(fuzz_logger_text.FuzzLoggerText(file_handle=logfile))
        # html table logger
        report_name = args.txtlog
        if report_name.find('/') != -1:
            report_name = report_name[report_name.rindex('/')+1:]

        # HTML table format output, used for result displaying
        fuzz_loggers.append(fuzz_logger_html_table.FuzzLoggerHtmlTable(report_name=report_name))
    # json data logger
    if args.jsonlog:
        json_log_file = open(args.jsonlog, "w+")

        # json format output, used for result analysing
        fuzz_loggers.append(fuzz_logger_json.FuzzLoggerJson(file_handle=json_log_file, report_name=report_name))

    if not fuzz_loggers:
        fuzz_loggers = [fuzz_logger_text.FuzzLoggerText(file_handle=sys.stdout)]

    try:
        port = y["test"]["session"]["target"]["port"]
        ip_p = y["test"]["session"]["target"]["ip_p"]
        if isinstance(port, str):
            port = int(port)
        session = Session(
            target=Target(
                connection=SocketConnection(y["test"]["session"]["target"]["ip"],
                                            port,
                                            proto=y["test"]["session"]["target"]["protocol"],
                                            bind=bind,
                                            ip_header_proto_num=ip_p)),
            fuzz_loggers = fuzz_loggers,
            sleep_time=1.0)
        pre_status = ""

        for status in y["test"]["status"]:
            add_status(status)

        for status in y["test"]["status"]:
            if pre_status == "":
                session.connect(s_get(status["status_name"]))
                pre_status = status["status_name"]
            else:
                session.connect(pre_status, s_get(status["status_name"]))
                pre_status = status["status_name"]

        if not only_generate:
            session.fuzz()
        else:
            print session.num_mutations()
    except Exception as e:
        print "error: " + str(e)
        traceback.print_exc()


if __name__ == "__main__":
    main()
