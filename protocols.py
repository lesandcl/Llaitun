import scapy.all
scapy.all.load_contrib('ospf')
scapy.all.load_contrib('eigrp')
scapy.all.load_contrib("lldp")
REPORTE = []
REPORTE_HOST = []


def reporte(mac, ip, vuln):
    global REPORTE
    if not [mac, ip, vuln] in REPORTE:
        REPORTE.append([mac, ip, vuln])


def reporte_host(src, psrc):
    global REPORTE_HOST
    if not [src, psrc] in REPORTE_HOST:
        REPORTE_HOST.append([src, psrc])


def reporte_host(src, psrc):
    global REPORTE_HOST
    if not [src, psrc] in REPORTE_HOST:
        REPORTE_HOST.append([src, psrc])


def HOST_ACTIVOS_ARP(PDU):
    if PDU.op == 1:
        reporte_host(PDU.src, PDU.psrc)


def PROT_L2_LLDP(PDU):
    if PDU.type == 35020:
        reporte(PDU.src, "-", "LLDP")


def PROT_L2_CISCO(PDU):
    if PDU.OUI == 12 and PDU.code == 273:
        reporte(PDU.src, "-", "Cisco-UDLD")
    elif PDU.OUI == 12 and PDU.code == 8192:
        reporte(PDU.src, "-", "Cisco-CDP")
    elif PDU.OUI == 12 and PDU.code == 8195:
        reporte(PDU.src, "-", "VTP")
    elif PDU.OUI == 12 and PDU.code == 8196:
        reporte(PDU.src, "-", "Cisco-DTP")
    elif PDU.type == 33024:
        reporte(PDU.src, "-", "Cisco-DOT1Q")
    elif PDU.dst == "01:00:0c:cc:cc:cd":
        reporte(PDU.src, "-", "PVST")
    else:
        reporte(PDU.src, PDU.payload.src, "Cisco Protocols")


def IPv4OSPF_L3_AUTH(PDU):
    if PDU.authtype == 0:
        reporte(PDU.src, PDU.payload.src, "OSPF not authenticated")
    elif PDU.authtype == 1:
        reporte(PDU.src, PDU.payload.src, "OSPF plain text authentication")
    elif PDU.authtype == 2:
        reporte(PDU.src, PDU.payload.src, "OSPF MD5 authentication")
    else:
        reporte(PDU.src, PDU.payload.src, "OSPF")


def IPv4EIGRP_L3_AUTH(PDU):
    if len(PDU.tlvlist) == 2:
        reporte(PDU.src, PDU.payload.src, "EIGRP not authenticated")
    else:
        reporte(PDU.src, PDU.payload.src, "EIGRP authenticated")


def IPv4RIP_L3_AUTH(PDU):
    if PDU.sport == 520:
        if PDU.payload.payload.payload.version == 1 and PDU.payload.dst == '255.255.255.255':
            reporte(PDU.src, PDU.payload.src, "RIP Version 1")
        elif PDU.payload.payload.payload.version == 2:
            if PDU.AF == 2:
                reporte(PDU.src, PDU.payload.src, "RIP version 2 not authenticated")
            elif PDU.AF == 65535 and PDU.authtype == 2:
                reporte(PDU.src, PDU.payload.src, "RIP Version 2 plain text authentication")
            elif PDU.AF == 65535 and PDU.authtype == 3:
                reporte(PDU.src, PDU.payload.src, "RIP version 2 MD5 authentication")


def IPv4VRRP_FHRP(PDU):
    if PDU.authtype == 0:
        reporte(PDU.src, PDU.payload.src, "VRRP not authenticated")
    elif PDU.authtype == 1:
        reporte(PDU.src, PDU.payload.src, "VRRP plain text authentication")


def IPv4GLBP_FHRP(PDU):
    if PDU.sport == 3222:
        reporte(PDU.src, PDU.payload.src, "Cisco-GLBP not authenticated")


def IPv4HSRP_FHRP(PDU):
    if PDU.sport == 1985:
        if PDU.auth.hex() == "636973636f000000":
            reporte(PDU.src, PDU.payload.src, "HSRP not authenticated (default)")
        if PDU.auth.hex() == "0000000000000000" and PDU.payload.payload.payload.payload.algo == 1:
            reporte(PDU.src, PDU.payload.src, "MD5 authentication")
        else:
            reporte(PDU.src, PDU.payload.src, "Plain text authentication")
