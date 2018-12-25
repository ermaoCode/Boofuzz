from __future__ import print_function
import sys
import datetime
import time
import json

from . import ifuzz_logger_backend








class FuzzLoggerJson(ifuzz_logger_backend.IFuzzLoggerBackend):
    """
    This class formats FuzzLogger data for pcap file. It can be
    configured to output to a named file.
    """

    def __init__(self, report_name, file_handle=sys.stdout):
        """
        Args:
            file_hanlde (io.TextIOBase): Open file handle for logging. Defaults to sys.stdout.
            bytes_to_str (function): Function that converts sent/received bytes data to string for logging.
        """
        self._file_handle = file_handle
        self._report_name = report_name

        self.json_result = {}
        self.json_result['testName'] = report_name
        self.json_result['testAll'] = 0
        self.json_result['testPass'] = 0
        self.json_result['testFail'] = 0
        self.json_result['testSkip'] = 0
        self.json_result['beginTime'] = int(round(time.time() * 1000))

        self.json_result['totalTime'] = 0

        self.prev_result = {}
        self.print_start()

    def open_test_step(self, description):
        pass

    def log_check(self, description):
        # self._print_log_msg(["check", "", description])
        pass

    def log_recv(self, data):
        # self._print_log_msg(["recv", len(data), self._format_raw_bytes(data), data])
        # self.prev_result["ReceiveData"] = data
        pass

    def log_send(self, data):
        # self._print_log_msg(["send", len(data), self._format_raw_bytes(data), data])
        # self.prev_result["SendData"] = data
        pass

    def log_info(self, description):
        # self._print_log_msg(["info", "", description])
        pass

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        if (self.prev_result):
            self.json_result['testAll'] += 1
            self.json_result['testPass'] += 1
            self.print_case(self.prev_result)
            self._print_log_msg(",")

        self.prev_result["id"] = test_case_id
        self.prev_result["timestamp"] = int(round(time.time() * 1000))
        self.prev_result["fuzzing_path"] = name
        self.prev_result["status"] = name
        self.prev_result["spend_time"] = ""
        self.prev_result["result"] = "success"


    def log_error(self, description):
        self.prev_result["result"] = "fail"
        self.json_result['testAll'] += 1
        self.json_result['testFail'] += 1
        self.print_case(self.prev_result)
        self.print_finish()

    def log_fail(self, description=""):
        # self._print_log_msg(["fail", "", description])
        self.log_error(description)

    def log_pass(self, description=""):
        # self._print_log_msg(["pass", "", description])
        self.prev_result["Result"] = "success"
        self.json_result['testAll'] += 1
        self.json_result['testPass'] += 1
        self.print_case(self.prev_result)
        self.print_finish()

    def print_case(self, case_description):
        cur_time = int(round(time.time() * 1000))
        self.prev_result["spend_time"] = cur_time - self.prev_result["timestamp"]
        res = json.dumps(case_description)
        self._print_log_msg(res)

    def print_start(self):
        self._print_log_msg("{\n\"testResult\":[")

    def print_finish(self):
        self.json_result['totalTime'] = int(round(time.time() * 1000)) - self.json_result['beginTime']

        self._print_log_msg("], \"meta\":")
        self._print_log_msg(json.dumps(self.json_result))
        self._print_log_msg("}\n")



    def _print_log_msg(self, msg):
        print(msg, file=self._file_handle)


