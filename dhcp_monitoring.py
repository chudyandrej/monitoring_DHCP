#!/usr/bin/python
import sys
import ipaddress
from struct import *
import socket
import pcapy
import threading
from pcapy import open_live, findalldevs, PcapError
import signal
import sys
import curses
import time



networks = []
dictOfUsedIpAddresses = dict()
modifyFlag = True

class Network:
    def __init__(self, addressAndPrefix):
        self.networkAddr = addressAndPrefix
        self.allocatedAddresses = 0
        self.allHosts = list(ipaddress.ip_network(unicode(addressAndPrefix)).hosts())
        self.maxHosts = len(self.allHosts)

    def getStatistics(self):
        return round((float(self.allocatedAddresses) / float(self.maxHosts)) * 100, 2)

    def incOccupiedAddress(self):
        global modifyFlag
        self.allocatedAddresses += 1
        modifyFlag = True
    def decOccupiedAddress(self):
        global modifyFlag
        self.allocatedAddresses -= 1
        modifyFlag = True

    def isIn(self, address):
        if ipaddress.ip_address(unicode(address)) >= self.allHosts[0] and ipaddress.ip_address(unicode(address)) <= self.allHosts[-1]:
            return True
        return False



class IpAddress:
    def __init__(self, ipAddress, leaseTime):
        self.membershipInNetworks = []
        self.ipAddress = ipAddress
        for network in networks:
            if network.isIn(ipAddress):
                self.membershipInNetworks.append(network)
                network.incOccupiedAddress()
        if len(self.membershipInNetworks) > 0:
            self.timer = threading.Timer(leaseTime, deleteAddress, args=[self.ipAddress])
            self.timer.start()

    def reset(self, leaseTime):
        self.timer.cancel()
        self.timer = threading.Timer(leaseTime, deleteAddress, args=[self.ipAddress])
        self.timer.start()

class Curese:
    def __init__(self):
        self.screen = curses.initscr()
        self.sizeWindow = self.screen.getmaxyx()
        self.setMenu()


    def setMenu(self):
        try:
            self.screen.border(0)
            self.screen.addstr(1, 3, "IP Prefix", curses.A_BOLD |curses.A_UNDERLINE )
            self.screen.addstr(1, int(self.sizeWindow[1] * 3/10), "Max hosts", curses.A_BOLD |curses.A_UNDERLINE )
            self.screen.addstr(1, int(self.sizeWindow[1] * 5/10), "Allocated addresses" , curses.A_BOLD |curses.A_UNDERLINE )
            self.screen.addstr(1, int(self.sizeWindow[1] * 8/10), "Utilization", curses.A_BOLD |curses.A_UNDERLINE )
        except:
            pass

    def refresh(self):
        try:
            global modifyFlag
            if not self.screen.getmaxyx() == self.sizeWindow or modifyFlag:
                self.screen.clear()
                self.sizeWindow = self.screen.getmaxyx()
                modifyFlag = False
                self.setMenu()

                line = 3
                for net in networks:
                    self.screen.addstr(line, 3, str(net.networkAddr))  # Row 10, row 30
                    self.screen.addstr(line, int(self.sizeWindow[1] * 3/10), str(net.maxHosts))
                    self.screen.addstr(line, int(self.sizeWindow[1] * 5/10), str(net.allocatedAddresses))
                    self.screen.addstr(line, int(self.sizeWindow[1] * 8/10), str(net.getStatistics()))
                    line += 1

            self.screen.refresh()
        except:
            pass


def deleteAddress(ipAddress):
    instanceToDelete = dictOfUsedIpAddresses.pop(ipAddress)
    for network in instanceToDelete.membershipInNetworks:
        network.decOccupiedAddress()

def signal_handler(signal, frame):
        curses.endwin()
        sys.exit(0)

def parse_packet(packet) :

    #parse ethernet header
    eth_length = 14
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])


    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
          #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]

        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]

        #UDP packets
        if protocol == 17 :
            u = iph_length + eth_length
            udp_header = packet[u:u+8]

            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)
            source_port = udph[0]
            if (source_port == 68 or source_port == 67):

                typeOfDhcpMessage = unpack('!BBB' , packet[283:286])
                if (typeOfDhcpMessage[1] == 5):
                    ip = unpack('!BBBB' , packet[58:62])
                    leaseTime = unpack('!i', packet[293:297])[0]
                    ackMessageService(str(ip[0]) + "." + str(ip[1]) + "." + str(ip[2]) + "." + str(ip[3]),leaseTime)

                if (typeOfDhcpMessage[1] == 7):
                    ipaddres = packet[54:58]
                    ip = unpack('!BBBB' , ipaddres)
                    releaseMessageService(str(ip[0]) + "." + str(ip[1]) + "." + str(ip[2]) + "." + str(ip[3]))

def ackMessageService(ipAddress, leaseTime):
    try:
        dictOfUsedIpAddresses[ipAddress].reset(leaseTime)
    except KeyError:
        dictOfUsedIpAddresses[ipAddress] = IpAddress(ipAddress,10)

def releaseMessageService(ipAddress):
    try:
        deleteAddress(ipAddress)
    except KeyError:
        pass


if len(sys.argv) < 2:
    print 'Error: Please enter network addresses as arguments.'
    sys.exit(1)


for networkIp in sys.argv[1:]:
    newNetwork = Network(networkIp)
    networks.append(newNetwork)

signal.signal(signal.SIGINT, signal_handler)

cap = pcapy.open_live("enp0s3" , 65536 , 1 , 0)

outputTable = Curese()

while(1) :
    (header, packet) = cap.next()
    parse_packet(packet)
    outputTable.refresh()
