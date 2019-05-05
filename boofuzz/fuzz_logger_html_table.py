from __future__ import print_function
import sys
import datetime
import csv

from . import helpers
from . import ifuzz_logger_backend


def hex_to_hexstr(input_bytes):
    """
    Render input_bytes as ASCII-encoded hex bytes, followed by a best effort
    utf-8 rendering.

    :param input_bytes: Arbitrary bytes.

    :return: Printable string.
    """
    return helpers.hex_str(input_bytes)


DEFAULT_HEX_TO_STR = hex_to_hexstr


def get_time_stamp():
    s = datetime.datetime.utcnow().isoformat()
    return s


def format_html_result(result):
    s = "<tr>"

    s += "<td>" + result["TestNumber"] + "</td>"
    s += "<td>" + result["TimeStamp"] + "</td>"
    s += "<td>" + result["Detail"] + "</td>"
    s += "<td>" + result["Result"] + "</td>"

    s += "</tr>"
    return s


class FuzzLoggerHtmlTable(ifuzz_logger_backend.IFuzzLoggerBackend):
    """
    This class formats FuzzLogger data for pcap file. It can be
    configured to output to a named file.
    """

    def __init__(self, report_name, file_handle=sys.stdout, bytes_to_str=DEFAULT_HEX_TO_STR):
        """
        Args:
            file_hanlde (io.TextIOBase): Open file handle for logging. Defaults to sys.stdout.
            bytes_to_str (function): Function that converts sent/received bytes data to string for logging.
        """
        self._file_handle = file_handle
        self._format_raw_bytes = bytes_to_str
        self._csv_handle = csv.writer(self._file_handle)
        self._report_name = report_name

        # self._print_log_msg("<table border='1'>")
        header = '''<tr><th>TestNumber</th><th>TimeStamp</th><th>Detail</th><th>Result</th></tr>'''
        self._print_log_msg(header)
        self.prev_result = {}

    def open_test_step(self, description):
        pass

    def log_check(self, description):
        # self._print_log_msg(["check", "", description])
        pass

    def log_recv(self, data):
        # self._print_log_msg(["recv", len(data), self._format_raw_bytes(data), data])
        self.prev_result["ReceiveData"] = data

    def log_send(self, data):
        # self._print_log_msg(["send", len(data), self._format_raw_bytes(data), data])
        self.prev_result["SendData"] = data

    def log_info(self, description):
        # self._print_log_msg(["info", "", description])
        pass

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        if (self.prev_result):
            self._print_log_msg(format_html_result(self.prev_result))

        self.prev_result["TestNumber"] = test_case_id
        self.prev_result["TimeStamp"] = get_time_stamp()
        self.prev_result["Detail"] = '<a href="/fuzz-gettestdetail/?reportname='+self._report_name+'&caseid='+str(index)+'" target="_blank">'+name+'</a>'
        self.prev_result["SendData"] = ""
        self.prev_result["ReceiveData"] = ""
        self.prev_result["Result"] = "Ok"

    def log_error(self, description):
        self.prev_result["Result"] = "error:" + description
        self._print_log_msg(format_html_result(self.prev_result))

    def log_fail(self, description=""):
        # self._print_log_msg(["fail", "", description])
        self.log_error(description)

    def log_pass(self, description=""):
        # self._print_log_msg(["pass", "", description])
        self.prev_result["Result"] = "Finished:" + description
        self._print_log_msg(format_html_result(self.prev_result))

    def _print_log_msg(self, msg):
        print(msg, file=self._file_handle)


