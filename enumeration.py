import scapy.all
import re
from termcolor import colored

DATA_REPORT = []

def detailed_report(rep):
    global DATA_REPORT
    if not [rep] in DATA_REPORT:
        DATA_REPORT.append([rep])

def cdp_protocol(p):
    scapy.all.load_contrib("cdp")
    # CDP Variables
    deviceName = ""
    softwareVersion = ""
    platform = ""
    ipAddr = ""
    intFace = ""
    capabilities = ""

    try:
        # Device Name
        deviceName = str(p[4].val).split("'")[1]
    except AttributeError:
        pass
    try:
        # Software Version
        softwareVersion = re.search(r"\(([A-Za-z0-9_-]+)\)",str(p[5].val).split("'")[1]).group(1) + ", " + str(p[5].val).split("Version ")[1].split(",")[0]
    except AttributeError:
        pass
    try:
        # Platform
        platform = str(p[6].val).split("'")[1]
    except AttributeError:
        pass
    try:
        # IP Address
        ipAddr = p[8].addr
    except AttributeError:
        pass
    try:
        # Interface
        intFace = str(p[0][9].iface).split("'")[1]
    except AttributeError:
        pass
    try:
        # Capabilities
        capabilities = str(p[10].cap).replace("+",", ")
    except AttributeError:
        pass
    
    # Report
    rep = colored("[+] Protocol: CDP" , "green") + colored("\n\tUsed for: device fingerprint", "yellow") + colored("\n\tSource MAC: ", "green") + p.src + colored("\n\tDevice Name: ", "green") + deviceName + colored("\n\tSoftware version: ", "green") + softwareVersion + colored("\n\tPlatform: ", "green") + platform + colored("\n\tIP Address: ", "green") + ipAddr + colored("\n\tInterface: ", "green") + intFace + colored("\n\tCapabilities: ", "green") + capabilities + "\n--------------------------------------------------------------"
    detailed_report(rep)

def lldp_protocol(p):
    scapy.all.load_contrib("lldp")
    # LLDP Variables
    deviceName = ""
    softwareVersion = ""
    ipAddr = ""
    intFaceId = ""
    intFaceDesc = ""
    capabilities = ""

    try:
        # Device Name
        deviceName = str(p[5].system_name).split("'")[1]
    except AttributeError:
        pass
    try:
        # Software Version
        softwareVersion = re.search(r"\(([A-Za-z0-9_-]+)\)",str(p[6].description).split("'")[1]).group(1) + ", " + str(p[6].description).split("Version ")[1].split(",")[0]
    except AttributeError:
        pass
    try:
        # IP Address
        ipList = scapy.all.hexstr(p[9].management_address).split(" ")
        ipAddr = ""
        i = 0
        for ip in ipList:
            ipAddr += str(int("0x" + ip, 16))
            if i == 3:
                break
            else:
                i += 1
                ipAddr += "."
    except AttributeError:
        pass
    try:
        # Interface ID
        intFaceId = str(p[3].id).split("'")[1]
    except:
        pass
    try:
        # Interface Description
        intFaceDesc = str(p[7].description).split("'")[1]
    except AttributeError:
        pass
    try:
        # Capabilities
        capabilities = ""
        if p[8].router_available == 1:
            capabilities += "Router, "
        if p[8].mac_bridge_available == 1:
            capabilities += "Bridge, "
        if p[8].telephone_available == 1:
            capabilities += "Telephone, "
        if p[8].docsis_cable_device_available == 1:
            capabilities += "DOCSIS cable device, "
        if p[8].wlan_access_point_available == 1:
            capabilities += "WLAN access point, "
        if p[8].repeater_available == 1:
            capabilities += "Repeater, "
        if p[8].station_only_available == 1:
            capabilities += "Station only, "
        if p[8].other_available == 1:
            capabilities += "Other, "
    except AttributeError:
        pass

    # Report
    rep = colored("[+] Protocol: LLDP", "green") + colored("\n\tUsed for: device fingerprint", "yellow") + colored("\n\tSource MAC: ", "green") + p.src + colored("\n\tDevice Name: ", "green") + deviceName + colored("\n\tSoftware version: ", "green") + softwareVersion + colored("\n\tIP Address: ", "green") + ipAddr + colored("\n\tInterface ID: ", "green") + intFaceId + colored("\n\tInterface Description: ", "green") + intFaceDesc + colored("\n\tCapabilities: ", "green") + capabilities[:-2] + "\n--------------------------------------------------------------"
    detailed_report(rep)