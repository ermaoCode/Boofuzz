import commands

def check_target(ip, port):
    res = 1
    res_str = "Checking %s:%s...\r"%(ip, port)
    # print "checking host: %s" % ip
    cmdStr = "ping -c 1 %s" % ip
    status, result = commands.getstatusoutput(cmdStr)
    if status == 0:
        # print("Host ON")
        res_str += "Host ON."
    else:
        # print("Host Off")
        res_str += "Host OFF."
        res = 0
    # print "checking service: port %s" % port
    cmdStr = "nmap %s -p %s -PS" % (ip, port)
    status, result = commands.getstatusoutput(cmdStr)
    if result.find("open") != -1:
        # print("Service ON")
        res_str += "Service ON."
    else:
        # print("Service Off")
        res_str += "Service OFF."
        res = 0
    return res, res_str


if __name__ == "__main__":
    res, res_str = check_target("10.21.5.156", 27)
    print (str(res) + res_str)
