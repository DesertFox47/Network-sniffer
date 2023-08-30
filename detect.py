#Author: Sourav S Adiga
#Python version -- Python 3.9.5
#To be used only on on compliance of all host systems on the intranet

#To capture all packets on the network interface and detect attacks by comparing parameters

#from number_of_devices_connected import ass_disass
import pyshark
import numpy as np
import time
from scapy.all import ARP, Ether, srp

def pack_anyls(a):
    # define interface
    networkInterface = "Wi-Fi"

    # define capture object
    capture = pyshark.LiveCapture(interface=networkInterface)

    print("listening on %s" % networkInterface)
    p2=[]
    flag=20

    # def apply_and(c):
    #     if len(c) > 1:
    #         return c[0] and apply_and(c[1:])
    #      else:
    #         return c[0]

    #detect attack by comparing parameters
    def check(localtime, src_addr, src_port, dst_addr, dst_port, protocol,p2):
        p1=[localtime, src_addr, src_port, dst_addr, dst_port, protocol]

        # a1=("p1[1]"=="p2[1]")
        # a2=("p1[1]"=="p2[3]")
        # a3=("p1[2]"=="p2[2]")
        # a4=("p1[2]"=="p2[4]")

        # if (a1 or a2) :
        #     if (a3 or a4):
        #         print(localtime + "\t Safe packet")
        # else :
        #     print(localtime + "\t Attack detected \t" + src_addr, src_port, dst_addr, dst_port, protocol)

        # print(a1,a2)
        # print(p1,p2)

        # print(a1,a2,a3,a4)
        
        c=((np.array(p1) == np.array(p2)))

        # if (apply_and(c)):
        if (c[1] or c[2] or c[3] or c[4]):
            print(localtime + "\t Safe packet")
        else:
            print(localtime + "\t Attack detected \t" + src_addr, src_port, dst_addr, dst_port, protocol)
    
        p2.clear()
        p2=p1
        
        # print(p1,p2)
        return 1,p2

    #while(1):
    for packet in capture.sniff_continuously(packet_count=10):
        # adjusted output
        try:
            # get timestamp
            localtime = time.asctime(time.localtime(time.time()))
        
            # get packet content
            protocol = packet.transport_layer   # protocol type
            src_addr = packet.ip.src            # source address
            src_port = packet[protocol].srcport   # source port
            dst_addr = packet.ip.dst            # destination address
            dst_port = packet[protocol].dstport   # destination port

            # output packet info
            print ("%s IP %s:%s <-> %s:%s (%s)" % (localtime, src_addr, src_port, dst_addr, dst_port, protocol))
            
            if flag==20:
                p2=[localtime, src_addr, src_port, dst_addr, dst_port, protocol]
            
            flag, p2 = check(localtime, src_addr, src_port, dst_addr, dst_port, protocol,p2)
            
        except AttributeError as e:
            # ignore packets other than TCP, UDP and IPv4
            pass
        print (" ")
    
    a=ass_disass(a)
    return a
    


def ass_disass(a):
    target_ip = "192.168.43.1/24"
    # IP Address for the destination
    # create ARP packet
    arp = ARP(pdst=target_ip)
    # create the Ether broadcast packet
    # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # stack them
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    # a list of clients, we will fill this in the upcoming loop
    clients = []

    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    # print clients
    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))
    
   
    
    count=len(clients)
    if count>a:
        print("Total number of devices on the network \t"+str(count)+"\n New devices joined")
    if count<a:
        print("Total number of devices on the network \t"+str(count)+"\n Devices disconnected from network")
    if count==a:
        print("Total number of devices on the network \t"+str(count))
    #a=count
    return count

n=0
r=0
while(r<2):
    n=pack_anyls(n)
    r=r+1
# if __name__ == '__main__':
#     c=0
#     #while(1)
#     pack_anyls()
#     c=number_of_devices_connected.ass_disass()


