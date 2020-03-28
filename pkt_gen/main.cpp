#include <in.h> // this is for using ntohs() and htons() on non-Windows OS's
#include "stdlib.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "HttpLayer.h"
#include "UdpLayer.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "PlatformSpecificUtils.h"
#include <time.h>

int main(int argc, char* argv[])
{

	// Packet Creation
	// ~~~~~~~~~~~~~~~
    std::string interfaceIPAddr(argv[1]);
    std::string destAddr(argv[2]);
    
    // Get device info
    // ~~~~~~~~~~~~~~~
    // find the interface by IP address
    pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr.c_str());
    if (dev == NULL)
    {
        printf("Cannot find interface with IPv4 address of '%s'\n", interfaceIPAddr.c_str());
        exit(1);
    }
    
    // before capturing packets let's print some info about this interface
    // printf("Interface info:\n");
    // // get interface name
    // printf("   Interface name:        %s\n", dev->getName());
    // // get interface description
    // printf("   Interface description: %s\n", dev->getDesc());
    // // get interface MAC address
    // printf("   MAC address:           %s\n", dev->getMacAddress().toString().c_str());
    // // get default gateway for interface
    // printf("   Default gateway:       %s\n", dev->getDefaultGateway().toString().c_str());
    // // get interface MTU
    // printf("   Interface MTU:         %d\n", dev->getMtu());
    
    // get DNS server if defined for this interface
    // if (dev->getDnsServers().size() > 0)
    //     printf("   DNS server:            %s\n", dev->getDnsServers().at(0).toString().c_str());

    // Get the dynamic MAC address for attached sender
    std::string lg_mac = dev->getMacAddress().toString();

    // open the device before start capturing/sending packets
    if (!dev->open())
    {
        printf("Cannot open device\n");
        exit(1);
    }

    printf("\nStarting capture with packet vector...\n");

    // create a new Ethernet layer
    int NUMBER_OF_PACKETS = atoi(argv[3]);
    int i = 0;
    clock_t t;
    t = clock();
    
    for (i = 0; i < NUMBER_OF_PACKETS; i++)
    {   
        // Dest. MAC is dummy
        pcpp::EthLayer newEthernetLayer(pcpp::MacAddress(lg_mac), pcpp::MacAddress("aa:bb:cc:dd:ee"), PCPP_ETHERTYPE_IP);

        // create a new IPv4 layer
        //SOURCE IP, DEST IP
        pcpp::IPv4Layer newIPLayer(pcpp::IPv4Address(interfaceIPAddr.c_str()), pcpp::IPv4Address(destAddr.c_str()));
        // pcpp::IPv4Layer newIPLayer();
        newIPLayer.getIPv4Header()->protocol = pcpp::PACKETPP_IPPROTO_UDP;
        newIPLayer.getIPv4Header()->ipVersion = 4;
        newIPLayer.getIPv4Header()->timeToLive = 64;
        newIPLayer.getIPv4Header()->typeOfService = 0;
        
        // newIPLayer.getIPv4Header()->totalLength = htons(38);

        // create a new UDP layer with dummy ports
        pcpp::UdpLayer newUdpLayer(12345, 12346);
        newUdpLayer.getUdpHeader()->length = htons(8);

        // create a packet with initial capacity of 100 bytes (will grow automatically if needed)
        pcpp::Packet newPacket;

        // add all the layers we created
        newPacket.addLayer(&newEthernetLayer);
        newPacket.addLayer(&newIPLayer);
        newPacket.addLayer(&newUdpLayer);

        // compute all calculated fields
        // newPacket.computeCalculateFields();
        
        if (!dev->sendPacket(&newPacket))
        {
            printf("Couldn't send packet\n");
            exit(1);
        }
    }
    t = clock() - t;
    printf("%d packets sent\n", NUMBER_OF_PACKETS);
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds
    printf("Sending took %f seconds \n", time_taken);
}