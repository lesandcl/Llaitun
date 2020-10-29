try:
    import getopt
    import sys
    import protocols
    import enumeration
    import scapy.all
    import uuid
    import sqlite3
    import random
    import os
    import ipaddress
    from termcolor import colored
except ImportError as err:
    print("Some libraries are missing:")
    print(err)
# Un comentario para mostrar cambio en git
def usage():
    print("OPTIONS:")
    print("-l/--live: live mode")
    print("-f/--file: read a pcap file")
    print("-a/--active-host: scan the active hosts")
    print("-d/--detail: see enumeration details (CDP/LLDP)")
    print("\n")
    print("If you are lost... you can try this:")
    print("python Llaitun.py --file <inputPcapFile>")
    print("\n")
    print("If you want to see the active hosts in your network, use:")
    print("python Llaitun.py -a <network>")
    print("\n")
    print("For more details, try this:")
    print("python Llaitun.py -d --file <inputPcapFile>")
    print("python Llaitun.py -d --live")
    print("\n")
    print("Or you can try live mode like this:")
    print("python Llaitun.py --live")
    print("\n")

def static(file_pcap,detail):
    if len(file_pcap) <= 0:
        print("You must enter the name of a file.")
        return
    try:
        with scapy.all.PcapReader(file_pcap) as pr:
            for pdu in pr:
                try:
                    if pdu.dst == "01:00:0c:cc:cc:cc":
                        protocols.PROT_L2_CISCO(pdu)
                        if detail:
                            enumeration.cdp_protocol(pdu)
                    elif pdu.dst == "01:80:c2:00:00:0e":
                        protocols.PROT_L2_LLDP(pdu)
                        if detail:
                            enumeration.lldp_protocol(pdu)
                    elif pdu.type == 2048:
                        if pdu.proto == 17 and pdu.payload.dst == '224.0.0.102':
                            protocols.IPv4GLBP_FHRP(pdu)
                        elif pdu.proto == 17:
                            protocols.IPv4RIP_L3_AUTH(pdu)
                        elif pdu.proto == 89:
                            protocols.IPv4OSPF_L3_AUTH(pdu)
                        elif pdu.proto == 88:
                            protocols.IPv4EIGRP_L3_AUTH(pdu)
                        elif pdu.proto == 112:
                            protocols.IPv4VRRP_FHRP(pdu)
                        else:
                            pass
                    elif pdu.type == 2054:
                        if detail:
                            protocols.HOST_ACTIVOS_ARP(pdu)
                    elif pdu.type == 34525:
                        pass
                except Exception as ex:
                    pass

            con = sqlite3.connect(':memory:')
            cursor = con.cursor()
            cursor.execute('''
                CREATE TABLE escaner_pasivo
                (MAC TEXT NOT NULL,
                 IP  TEXT,
                 VULN TEXT)
            ''')

            if len(protocols.REPORTE) > 0:
                print(colored(f"[{len(protocols.REPORTE)}] Vulnerable protocols detected!", "red"))
            else:
                print(colored("[0] vulnerable protocols detected!", "blue"))
                exit(0)

            for mac, ip, vuln in protocols.REPORTE:
                cursor.execute(
                    "insert into escaner_pasivo (mac, ip, vuln) values ('" + mac + "','" + ip + "', '" + vuln + "')")
                con.commit()
                print(
                    colored("[+] MAC: ", "green") + mac + colored(" IP: ", "green") + ip + colored(" Vulnerability: ",
                                                                                                   "red") + vuln)
            con.close()

            if len(protocols.REPORTE_HOST) > 0:
                print(colored(f"\n[{len(protocols.REPORTE_HOST)}] Active Host:", "red"))
            for mac, ip in protocols.REPORTE_HOST:
                print(colored("[+] MAC: ", "green") + mac + colored(" IP: ", "green") + ip)
                
            if len(enumeration.DATA_REPORT) > 0:
                print(colored(f"\n[{len(enumeration.DATA_REPORT)}] Enumeration:", "red"))
            else:
                exit(0)
            for data in enumeration.DATA_REPORT:
                print("".join(data))

    except IOError as fileError:
        print(fileError)

def check_root():
    if os.name == "posix":
        if os.geteuid() != 0:
            print(colored("\n[-] It is necessary to run the script like root", "red"))
            exit(1)

def live(detail):
    seconds = input(colored("Enter sniffing period in seconds: ", "green"))
    try:
        num_of_seconds = int(seconds)
    except Exception:
        print(colored("[!]: ", "red") + "You must provide integer")
        return
    try:
        interfaces, option = get_interface()
        def_gw_device = interfaces[option]
        print("Begin sniffing on: " + colored(str(def_gw_device), "green"))
        capture = scapy.all.sniff(iface=def_gw_device, timeout=num_of_seconds, filter="")
        pcap_file = write_pcap(capture)
        print("End capture.")
        static(pcap_file, detail)
    except Exception as ex:
        print(ex)
        print(colored("run as super user.", "red"))

def activeHosts(network):
    check_root()
    try:
        ipaddress.ip_network(network, False)
    except ValueError:
        print(colored("Invalid network", "red"))
        exit(1)
    print(colored("[*] WARNING: Llaitun is a passive scanner, but the -a/--active-hosts option performs an active scan.", "yellow"))
    do_active_scan = input(colored("Do you want to continue?[N/y]: ", "yellow"))
    if do_active_scan.lower() != "y":
        print("Bye!")
        exit(0)
    print(colored("\n[*] Active hosts:", "red"))
    hosts = scapy.all.arping(network,verbose=0)
    for host in hosts[0]:
        print(colored("[+] MAC: ", "green") + host[1].src + colored(" IP: ", "green") + host[1].psrc)

def write_pcap(capture):
    unique_filename = str(uuid.uuid4())
    pcap_file = "live_sniffed_" + unique_filename + ".pcap"
    scapy.all.wrpcap(pcap_file, capture)
    print(colored(pcap_file, "blue"))
    return pcap_file


def get_interface():
    """
    This function use psutil for extract interfaces from OS.
    :return:
    interfaces
    option
    """
    if sys.platform.__eq__("win32"):
        inter_list = scapy.all.get_windows_if_list()
    else:
        inter_list = scapy.all.get_if_list()
    interfaces = dict()
    i = 0
    for inter in inter_list:
        if sys.platform.__eq__("win32"):
            print(colored("[" + str(i) + "]: ", "green") + f"Name {inter['name']}, IPs: {inter['ips']}")
            interfaces[i] = inter['name']
        else:
            print(colored("[" + str(i) + "]: ", "green") + f"{inter}")
            interfaces[i] = inter
        i += 1
    option = input(colored("select the interface: ", "green"))
    while True:
        try:
            option = int(option)
            if option in range(i):
                break
            else:
                print(colored("[!]: ", "red") + "invalid option")
                option = input("select the interface: ")
        except Exception as ex:
            print(colored("You must enter the interface number", "red"))
            option = input(colored("select the interface: ", "green"))
    return interfaces, option


def main():
    detail = False
    try:
        print("\n")
        color_list = ["red", "green", "yellow", "blue", "magenta", "cyan", "white"]
        banner_color = random.choice(color_list)
        print(colored("""
██╗     ██╗      █████╗ ██╗████████╗██╗   ██╗███╗   ██╗
██║     ██║     ██╔══██╗██║╚══██╔══╝██║   ██║████╗  ██║
██║     ██║     ███████║██║   ██║   ██║   ██║██╔██╗ ██║
██║     ██║     ██╔══██║██║   ██║   ██║   ██║██║╚██╗██║
███████╗███████╗██║  ██║██║   ██║   ╚██████╔╝██║ ╚████║
╚══════╝╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
        """, banner_color))
        print("_"*55)
        print(colored("\t\nDeveloped by I+D at lesand.cl", "green"), end="")
        print(colored("\t\n@dpachecocl - @agustin_salas_f - @W0lf_F4ng", "green"), end="")
        print(colored("\t\nVersion 1.1\n", "green"), end="")
        print("_" * 55, end="\n\n")
        try:
            opts, args = getopt.getopt(sys.argv[1:], "df:lha:", ["detail", "file=", "live", "help", "active-hosts="])
            if not opts:
                usage()
        except getopt.GetoptError as err:
            print(err)
            usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt in ("-d", "--detail"):
                detail = True
        for opt, arg in opts:
            if opt in ("-a", "--active-hosts"):
                activeHosts(arg)
        for opt, arg in opts:
            if opt in "-h" or opt in "--help":
                usage()
                sys.exit()
            elif opt in ("-l", "--live"):
                check_root()
                live(detail)
            elif opt in ("-f", "--file"):
                static(arg, detail)
    except KeyboardInterrupt:
        print("Bye!")
    except Exception as err:
        print(err)


if __name__ == "__main__":
    main()
