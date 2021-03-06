import os
import glob
import logFilter
from lxml import etree


# Function to identify distinct event IDs from the logs
def scan(logName):
    errorMsg = ""
    eid = []
    filename = os.path.basename(logName)
    try:
        with open("output\\" + filename + "_Event_ID_Scan.txt", "w") as f:
            f.write("The following Event IDs are found in " + filename + ":\n")
            print("The following Event IDs are found in " + filename + ":")
            for node, err in logFilter.xml_records(logName):
                if err is not None:
                    continue
                sys = logFilter.get_child(node, "System")
                seid = int(logFilter.get_child(sys, "EventID").text)
                if seid not in eid:
                    eid.append(seid)
                    print("Event ID: " + str(seid) + "\tLog File Name: " + str(filename))
                    f.write("\nEvent ID: " + str(seid) + "\tLog File Name: " + str(filename))
        f.close()
        os.startfile("output\\" + filename + "_Event_ID_Scan.txt")
    except KeyError:
        errorMsg = "There was an error scanning one or more of the log files."
    if errorMsg is not None:
        print(errorMsg)


# Function to parse events out to xml file based on user's criteria
def listAll(logName, userChoice):
    errorFiles = ""
    distintEid = []
    filename = os.path.basename(logName)
    outputFile = filename
    if userChoice == "*":
        ueid = userChoice
    elif userChoice == "appAuto":
        with open("appEidList.txt") as f:
            ueid = [int(x) for x in f.read().split()]
            f.close()
        outputFile = "Suspicious_Application_Log"
    elif userChoice == "securityAuto":
        with open("secEidList.txt") as f:
            ueid = [int(x) for x in f.read().split()]
            f.close()
        outputFile = "Suspicious_Security_Log"
    elif userChoice == "systemAuto":
        with open("sysEidList.txt") as f:
            ueid = [int(x) for x in f.read().split()]
            f.close()
        outputFile = "Suspicious_System_Security_Log"
    else:
        ueid = int(userChoice)
    try:
        with open("output\\" + outputFile + ".xml", "w", encoding="utf-8") as f:
            f.write(
                "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n<!--" + outputFile + "-->\n<Events>")
            for node, err in logFilter.xml_records(logName):
                if err is not None:
                    continue
                sys = logFilter.get_child(node, "System")
                if ueid == "*":
                    print(etree.tostring(node, pretty_print=True))
                    f.write("\n" + etree.tostring(node, encoding='utf8').decode('utf8'))
                    seid = int(logFilter.get_child(sys, "EventID").text)
                    if seid not in distintEid:
                        distintEid.append(seid)
                elif userChoice == "appAuto" or userChoice == "securityAuto" or userChoice == "systemAuto":
                    if int(logFilter.get_child(sys, "EventID").text) in ueid:
                        print(etree.tostring(node, pretty_print=True))
                        f.write("\n" + etree.tostring(node, encoding='utf8').decode('utf8'))
                        seid = int(logFilter.get_child(sys, "EventID").text)
                        if seid not in distintEid:
                            distintEid.append(seid)
                elif ueid == int(logFilter.get_child(sys, "EventID").text):
                    print(etree.tostring(node, pretty_print=True))
                    f.write("\n" + etree.tostring(node, encoding='utf8').decode('utf8'))
                    seid = int(logFilter.get_child(sys, "EventID").text)
                    if seid not in distintEid:
                        distintEid.append(seid)
            f.write("</Events>")
        f.close()
        os.startfile("output\\" + outputFile + ".xml")
        if type(ueid) == str:
            with open("output\\" + outputFile + ".txt", "w") as f:
                f.write("The following Event IDs are found in " + filename + ":")
                print("The following Event IDs are found in " + filename + ":")
                for ids in distintEid:
                    print("Event ID: " + str(ids) + "\tLog File Name: " + filename)
                    f.write("\nEvent ID: " + str(ids) + "\tLog File Name: " + filename)
            f.close()
            os.startfile("output\\" + outputFile + ".txt")
    except KeyError:
        errorFiles += logName + "\n"
    return errorFiles


# Function to generate file path and perform log analysis by running the other functions
def analyse(dir):
    dirAdd = dir + "\*.evtx"
    errorFiles = ""

    print("Scanning for log files...")
    logFiles = []
    for l in glob.glob(dirAdd):
        logFiles.append(os.path.basename(l))
    counter = 1
    for lf in logFiles:
        print(str(counter) + ":\t" + lf)
        counter += 1
    print(str(counter) + ":\t" + "*ALL LOGS\n" + str(counter + 1) + ":\t" + "**Automated Scan for suspicious events")
    scanOption = int(input("Enter numerical value of your choice of log file scan: "))

    print("Checking for output directory...")
    if not os.path.exists("output"):
        print("Output directory not found.\nCreating...")
        os.makedirs("output")
        print("Creation successful.")
    else:
        print("Output directory found.")

    if scanOption == len(logFiles) + 1:
        print("Scanning all logs, please wait...\n")
        for l in glob.glob(dirAdd):
            scan(l)
    elif scanOption == len(logFiles) + 2:
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
        return
    else:
        l = dir + "\\" + logFiles[scanOption - 1]
        scan(l)

    ueid = input("Enter Event ID to list all events with the same Event Id  (Enter \'*\' to list all Event IDs or "
                 "\'end\' to stop and return to main menu.): ")
    if ueid == "end":
        return

    if scanOption == len(logFiles) + 1:
        for l in glob.glob(dirAdd):
            errorFiles = listAll(l, ueid)
    else:
        errorFiles = listAll(l, ueid)
    if errorFiles != "":
        print("The following file(s) is/are not processed due to unforeseen error:\n" + errorFiles)
    else:
        print("Scan completed without errors.")
