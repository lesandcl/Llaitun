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


# modificacion dpacheco 28 nov
def HOST_ACTIVOS_ARP(PDU):
    if PDU.dst == "ff:ff:ff:ff:ff:ff":
        reporte_host(PDU.src, PDU.psrc)


def PROT_L2_LLDP(PDU):
    if PDU.type == 35020:
        reporte(PDU.src, "-", "LLDP")


def PROT_L2_CISCO(PDU):
    if PDU.OUI == 12 and PDU.code == 273:
        # print("Cisco-UDLD")
        reporte(PDU.src, "-", "Cisco-UDLD")
    elif PDU.OUI == 12 and PDU.code == 8192:
        # print("Cisco-CDP")
        reporte(PDU.src, "-", "Cisco-CDP")
    elif PDU.OUI == 12 and PDU.code == 8195:
        # print("Cisco-VTP")
        reporte(PDU.src, "-", "VTP")
    elif PDU.OUI == 12 and PDU.code == 8196:
        # print("Cisco-DTP")
        reporte(PDU.src, "-", "Cisco-DTP")
    elif PDU.type == 33024:
        # print("Cisco-DOT1Q")
        reporte(PDU.src, "-", "Cisco-DOT1Q")
    elif PDU.dst == "01:00:0c:cc:cc:cd":
        # print("PVST")
        reporte(PDU.src, "-", "PVST")
    else:
        # print("Protocolo Cisco ")
        reporte(PDU.src, PDU.payload.src, "Protocolo Cisco")


def IPv4OSPF_L3_AUTH(PDU):
    if PDU.authtype == 0:
        # print("OSPF Sin Autenticacion")
        reporte(PDU.src, PDU.payload.src, "OSPF Sin Autenticacion")
    elif PDU.authtype == 1:
        # print("OSPF Texto Plano")
        reporte(PDU.src, PDU.payload.src, "OSPF Texto Plano")
    elif PDU.authtype == 2:
        # print("OSPF MD5")
        reporte(PDU.src, PDU.payload.src, "OSPF MD5")
    else:
        # print("OSPF")
        reporte(PDU.src, PDU.payload.src, "OSPF")


def IPv4EIGRP_L3_AUTH(PDU):
    #  modificar metodo no me gusta#
    if len(PDU.tlvlist) == 2:
        # print("EIGRP Sin Auth")
        reporte(PDU.src, PDU.payload.src, "EIGRP Sin Auth")
    else:
        # print("EIGRP Con Auth")
        reporte(PDU.src, PDU.payload.src, "EIGRP Con Auth")


def IPv4RIP_L3_AUTH(PDU):
    if PDU.sport == 520:
        if PDU.payload.payload.payload.version == 1 and PDU.payload.dst == '255.255.255.255':
            reporte(PDU.src, PDU.payload.src, "RIP Version 1")
        elif PDU.payload.payload.payload.version == 2:
            if PDU.AF == 2:
                # print("RIP version 2 sin authenticacion")
                reporte(PDU.src, PDU.payload.src, "RIP version 2 sin authenticacion")
            elif PDU.AF == 65535 and PDU.authtype == 2:
                # print("RIP Version 2 Con autenticacion en texto plano")
                reporte(PDU.src, PDU.payload.src, "RIP Version 2 Con autenticacion en texto plano")
            elif PDU.AF == 65535 and PDU.authtype == 3:
                # print("RIP version 2 Con autenticacion MD5")
                reporte(PDU.src, PDU.payload.src, "RIP version 2 Con autenticacion MD5")


def IPv4VRRP_FHRP(PDU):
    # Falta probar con captura con MD5#
    if PDU.authtype == 0:
        # print("VRRP Sin Authenticacion")
        reporte(PDU.src, PDU.payload.src, "VRRP Sin Authenticacion")
    elif PDU.authtype == 1:
        # print("VRRP Autenticacion Texto Plano")
        reporte(PDU.src, PDU.payload.src, "VRRP Autenticacion Texto Plano")


def IPv4GLBP_FHRP(PDU):
    if PDU.sport == 3222:
        # Faslta agregar opciones de autenticacion#
        reporte(PDU.src, PDU.payload.src, "Cisco-GLBP")


def IPv4HSRP_FHRP(PDU):
    if PDU.sport == 1985:
        if PDU.auth.hex() == "636973636f000000":
            # print("HSRP Sin authenticacion (default)")
            reporte(PDU.src, PDU.payload.src, "HSRP Sin authenticacion (default)")
        if PDU.auth.hex() == "0000000000000000" and PDU.payload.payload.payload.payload.algo == 1:
            # print("Autenticacion MD5")
            reporte(PDU.src, PDU.payload.src, "Autenticacion MD5")
        else:
            # print("Autenticacion Texto Plano")
            reporte(PDU.src, PDU.payload.src, "Autenticacion Texto Plano")
