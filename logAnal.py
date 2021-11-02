from lxml import etree
import logFilter

import glob
import os


def scan(logName):
    eid = []
    filename = os.path.basename(logName)
    try:
        for node, err in logFilter.xml_records(logName):
            if err is not None:
                continue
            sys = logFilter.get_child(node, "System")
            seid = int(logFilter.get_child(sys, "EventID").text)
            if seid not in eid:
                eid.append(seid)
                print("Event ID: " + str(seid) + "\tLog File Name: " + str(filename))
    except KeyError:
        print("There was an error scanning one or more of the log files.")


def listAll(logName, ueid):
    errorFiles = ""
    # filename = os.path.splitext(os.path.basename(l))[0] + ".xml"
    try:
        for node, err in logFilter.xml_records(logName):
            if err is not None:
                continue
            sys = logFilter.get_child(node, "System")
            if ueid == "*":
                print(etree.tostring(node, pretty_print=True))
            elif ueid == "appAuto":
                with open("appEidList.txt") as f:
                    secEid = [int(x) for x in f.read().split()]
                if int(logFilter.get_child(sys, "EventID").text) in secEid:
                    print(etree.tostring(node, pretty_print=True))
            elif ueid == "securityAuto":
                with open("secEidList.txt") as f:
                    secEid = [int(x) for x in f.read().split()]
                if int(logFilter.get_child(sys, "EventID").text) in secEid:
                    print(etree.tostring(node, pretty_print=True))
            elif ueid == "systemAuto":
                with open("sysEidList.txt") as f:
                    secEid = [int(x) for x in f.read().split()]
                if int(logFilter.get_child(sys, "EventID").text) in secEid:
                    print(etree.tostring(node, pretty_print=True))
            elif int(ueid) == int(logFilter.get_child(sys, "EventID").text):
                print(etree.tostring(node, pretty_print=True))
    except KeyError:
        errorFiles += logName + "\n"
    return errorFiles


def analyse(dir):
    dirAdd = dir+"\*.evtx"
    errorFiles = ""

    print("Scanning for log files...")
    logFiles = []
    for l in glob.glob(dirAdd):
        logFiles.append(os.path.basename(l))
    counter = 1
    for lf in logFiles:
        print(str(counter) + ":\t" + lf)
        counter += 1
    print(str(counter) + ":\t" + "*ALL LOGS\n" + str(counter+1) + ":\t" + "**Automated Scan for suspicious events")
    scanOption = int(input("Enter numerical value of your choice of log file scan: "))

    if scanOption == len(logFiles)+1:
        print("Scanning all logs, please wait...\n")
        for l in glob.glob(dirAdd):
            scan(l)
    elif scanOption == len(logFiles)+2:
        print("Starting automated scan on Application log...\n")
        l = dir + "\\" + "Application.evtx"
        errorFiles = listAll(l, "appAuto")
        if errorFiles is not None:
            print("Scan complete.")
        else:
            print("Scan completed with errors processing the following:\n" + errorFiles)
        print("Starting automated scan on Security log...")
        l = dir + "\\" + "Security.evtx"
        errorFiles = listAll(l, "securityAuto")
        if errorFiles is not None:
            print("Scan complete.")
        else:
            print("Scan completed with errors processing the following:\n" + errorFiles)
        print("Starting automated scan on System log...")
        l = dir + "\\" + "System.evtx"
        errorFiles = listAll(l, "systemAuto")
        if errorFiles is not None:
            print("Scan complete.")
        else:
            print("Scan completed with errors processing the following:\n" + errorFiles)
        quit()
    else:
        l = dir + "\\" + logFiles[scanOption-1]
        scan(l)

    ueid = input("State Event ID to list all happenings (Enter \'*\' to list all Event IDs): ")

    if scanOption == len(logFiles)+1:
        for l in glob.glob(dirAdd):
            errorFiles = listAll(l, ueid)
    else:
        errorFiles = listAll(l, ueid)
    print("The following file(s) is/are not processed due to unforeseen error:\n" + errorFiles)

