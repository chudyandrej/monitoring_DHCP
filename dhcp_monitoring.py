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
import csv

networks = []
allocatedIpAddress = dict()
modifyFlag = True

class Network:
    """
        Network class. All informations about netowrk
    """ 
    def __init__(self, addressAndPrefix):
        self.networkAddr = addressAndPrefix
        self.allocatedAddresses = 0

        ipAddresPrefix = addressAndPrefix.split('/', 1 )
        self.prefixNetwork = int(ipAddresPrefix[1])
        if self.prefixNetwork == 32:
            self.allHosts = []
            self.allHosts.append(ipaddress.ip_address(unicode(ipAddresPrefix[0])) + 1)
        else:
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


class IpAddress:
    """
        Class Ip address.
    """ 
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


class Curese:
    """
        Window whit statistics.
    """ 
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
                    self.screen.addstr(line, int(self.sizeWindow[1] * 8/10), str(net.getStatistics()) + "%")
                    line += 1
            #refresh window
            self.screen.refresh()   
        except:
            pass

class ExportCSV:
    """
        Write log to file
    """ 
    def __init__(self, period):
        csvfile = open('log.csv', 'wb')
        csvfile.close()
        self.t = threading.Thread(target=self.loging, args=(period,))
        self.t.daemon = True
        self.t.start()

    def loging(self, period):
        csvfile = open('log.csv', 'ab')
        spamwriter = csv.writer(csvfile, delimiter=',')
        spamwriter.writerow(["IP Prefix", "Max hosts",
                   "Allocated addresses", "Utilization", "Time (M/D/Y H:M:S)"])
       
        while True:
            time.sleep(float(period))
            for net in networks:
                spamwriter.writerow([net.networkAddr, str(net.maxHosts), str(net.allocatedAddresses), 
                                    str(net.getStatistics()) + "%", time.strftime('%x %X')])


def deleteAddress(ipAddress):
    """
        Remove ip address object from dictionary and decrement statistics.
        Arguments:
            - ipAddress = ip address in string
    """
    instanceToDelete = allocatedIpAddress.pop(ipAddress)
    instanceToDelete.deactivateTimer()
    for network in instanceToDelete.membershipInNetworks:
        network.decOccupiedAddress()



def serviceDHCPmessage(packet):
    """
        Define service for DHCP message. ACK or Release
        Arguments:
            - packet = raw packet data in array
    """
    typeOfDhcpMessage = unpack('!BBB' , packet[285:288])
    # Ack message
    if (typeOfDhcpMessage[1] == 5):
        ip = unpack('!BBBB' , packet[60:64])
        leaseTime = unpack('!i', packet[295:299])[0]
        ackMessageService(str(ip[0])+ "." +str(ip[1])+ "." +str(ip[2])+ "." +str(ip[3]),leaseTime)
    # Release message
    if (typeOfDhcpMessage[1] == 7):
        ip = unpack('!BBBB' , packet[56:60])
        releaseMessageService(str(ip[0])+ "." +str(ip[1])+ "." +str(ip[2])+ "." +str(ip[3]))

def parse_packet(packet) :
    """
        Parse pacekt. First find ethernet protocol, then transport protocol, 
        then ports and call service of DHCP messages
        Arguments:
            - packet = raw packet data in array
    """
    #parse ethernet header
    eth_length = 14
    eth = unpack('!6s6sH' , packet[2:16])
    eth_protocol = socket.ntohs(eth[2])

    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
        iph = unpack('!BBHHHBBH4s4s' , packet[16:36])
        protocol = iph[6]
        #UDP packets
        if protocol == 17 :
            #udp header
            udph = unpack('!HHHH' , packet[36:44])
            source_port = udph[0]
            if (source_port == 68 or source_port == 67):
                serviceDHCPmessage(packet)
              
               
def ackMessageService(ipAddress, leaseTime):           
    """
        Define service for ACK message. Reste lease time or create new ip address in dictionary.
        Arguments:
            - ipAddress = ip address in string type
            - leaseTime = the time of validity 
    """ 
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
    """
        Define service for Release message. Remove ip address from statistics and dictionary.
        Arguments:
            - ipAddress = ip address in string type
    """  
    try:
        deleteAddress(ipAddress)
    except KeyError:
        pass

 
def signal_handler(signal, frame):
    """
        Define service for ctrl + c. Before end program curses must end window.
        Arguments:
            - signal 
            - frame
    """ 
    curses.endwin()  
    sys.exit(0)



def main():
    """
        Main function of porgram
    """  
    if len(sys.argv) < 2: 
        print 'Error: Please enter network addresses as arguments.'
        sys.exit(1)
    flagC = False
    interval = None

    try:
        for arg in sys.argv[1:]:
            if flagC:
                interval = int(arg)
                flagC = False
                continue;
            elif arg == "-c" and not arg == sys.argv[-1]:
                flagC = True
                continue;
            networks.append(Network(arg))
    except :
        print 'Error: Bad format of network address or other arguments'
        sys.exit(1)


    #Re-define ctrl + c service 
    signal.signal(signal.SIGINT, signal_handler)

    #Open interface 
    cap = pcapy.open_live("any", 57600, 1, 0)

   
    if not interval == None:
        csvExporter = ExportCSV(interval)

    #Init window in output terminal
    outputWindow = Curese()
   

    #main loop
    while(1) :

        (header, packet) = cap.next()
        parse_packet(packet)
        outputWindow.refresh()
        

if __name__ == "__main__":
    main()