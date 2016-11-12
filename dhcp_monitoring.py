#!/usr/bin/python
import sys
import ipaddress
from struct import *
import socket
import pcapy
import threading

import signal
import curses
import time

networks = []
allocatedIpAddress = dict()
modifyFlag = True

# Network class. All informations about netowrk
class Network:
    def __init__(self, addressAndPrefix):
        self.networkAddr = addressAndPrefix
        self.allocatedAddresses = 0
        #generate all hosts this network
        self.allHosts = list(ipaddress.ip_network(unicode(addressAndPrefix)).hosts())
        self.maxHosts = len(self.allHosts)
    #Return statistics about filling in percent
    def getStatistics(self):
        return round((float(self.allocatedAddresses) / float(self.maxHosts)) * 100, 2)
    #New host ip allocated
    def incOccupiedAddress(self):
        global modifyFlag
        self.allocatedAddresses += 1
        modifyFlag = True
    #Host is released
    def decOccupiedAddress(self):
        global modifyFlag
        self.allocatedAddresses -= 1
        modifyFlag = True
    # Is ip addres in this network   True / Fasle
    def isIn(self, address):
        if ipaddress.ip_address(unicode(address)) >= self.allHosts[0] and ipaddress.ip_address(unicode(address)) <= self.allHosts[-1]:
            return True
        return False

# Class Ip address
class IpAddress:
    def __init__(self, ipAddress, leaseTime):
        self.membershipInNetworks = []
        self.ipAddress = ipAddress
        self.leaseTime = leaseTime
        self.timer = None
    #Init live time of ipaddress
    def startTimer(self):
        self.timer = threading.Timer(self.leaseTime, deleteAddress, args=[self.ipAddress])
        self.timer.start()
    #Set new time
    def reset(self, leaseTime):
        self.timer.cancel()
        self.timer = threading.Timer(self.leaseTime, deleteAddress, args=[self.ipAddress])
        self.timer.start()

    def deactivateTimer(self):
        self.timer.cancel()
#Window whit statistics
class Curese:
    def __init__(self):

        self.screen = curses.initscr()
        #set size of window
        self.sizeWindow = self.screen.getmaxyx()
        #set menu on window
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
            #If size of the window been changed or is available a new statistics
            if not self.screen.getmaxyx() == self.sizeWindow or modifyFlag:
                self.screen.clear()
                #save new size of window
                self.sizeWindow = self.screen.getmaxyx()
                #deactive modify flag
                modifyFlag = False
                #re-paint menu
                self.setMenu()
                #print all statistics
                line = 3
                for net in networks:
                    self.screen.addstr(line, 3, str(net.networkAddr))  # Row 10, row 30
                    self.screen.addstr(line, int(self.sizeWindow[1] * 3/10), str(net.maxHosts))
                    self.screen.addstr(line, int(self.sizeWindow[1] * 5/10), str(net.allocatedAddresses))
                    self.screen.addstr(line, int(self.sizeWindow[1] * 8/10), str(net.getStatistics()))
                    line += 1
            #refresh window
            self.screen.refresh()
        except:
            pass


def deleteAddress(ipAddress):
    instanceToDelete = allocatedIpAddress.pop(ipAddress)
    instanceToDelete.deactivateTimer()
    for network in instanceToDelete.membershipInNetworks:
        network.decOccupiedAddress()

def serviceDHCPmessage(packet):
    typeOfDhcpMessage = unpack('!BBB' , packet[283:286])
    # Ack message
    if (typeOfDhcpMessage[1] == 5):
        ip = unpack('!BBBB' , packet[58:62])
        leaseTime = unpack('!i', packet[293:297])[0]
        ackMessageService(str(ip[0])+ "." +str(ip[1])+ "." +str(ip[2])+ "." +str(ip[3]),leaseTime)
    # Release message
    if (typeOfDhcpMessage[1] == 7):
        ip = unpack('!BBBB' , packet[54:58])
        releaseMessageService(str(ip[0])+ "." +str(ip[1])+ "." +str(ip[2])+ "." +str(ip[3]))


def parse_packet(packet) :
    #parse ethernet header
    eth_length = 14
    eth = unpack('!6s6sH' , packet[:14])
    eth_protocol = socket.ntohs(eth[2])

    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
        iph = unpack('!BBHHHBBH4s4s' , packet[14:34])

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]

        #UDP packets
        if protocol == 17 :
            u = iph_length + eth_length

            #udp header
            udph = unpack('!HHHH' , packet[u:u+8])
            source_port = udph[0]
            if (source_port == 68 or source_port == 67):
                serviceDHCPmessage(packet)


def ackMessageService(ipAddress, leaseTime):
    try:
        allocatedIpAddress[ipAddress].reset(leaseTime)
    except KeyError:
        #Create new address
        newIpaddress = IpAddress(ipAddress , 10)
        #If ip address is in network
        for network in networks:
            if network.isIn(ipAddress):
                newIpaddress.membershipInNetworks.append(network)
                network.incOccupiedAddress()
        if len(newIpaddress.membershipInNetworks):
            #Add address to dictionary
            newIpaddress.startTimer()
            allocatedIpAddress[ipAddress] = newIpaddress

def releaseMessageService(ipAddress):
    try:
        deleteAddress(ipAddress)
    except KeyError:
        pass

def signal_handler(signal, frame):
        curses.endwin()
        sys.exit(0)

def main():
    if len(sys.argv) < 2:
        print 'Error: Please enter network addresses as arguments.'
        sys.exit(1)
    try:
        for networkIp in sys.argv[1:]:
            networks.append(Network(networkIp))
    except:
        print 'Error: Bed format of network address.'
        sys.exit(1)
    #Re-define ctrl + c service
    signal.signal(signal.SIGINT, signal_handler)

    #Open interface
    cap = pcapy.open_live("enp0s3" , 65536 , 1 , 0)

    #Init window in output terminal
    outputWindow = Curese()

    #main loop
    while(1) :

        (header, packet) = cap.next()
        parse_packet(packet)
        outputWindow.refresh()


if __name__ == "__main__":
    main()
