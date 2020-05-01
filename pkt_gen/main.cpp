#include <in.h> // this is for using ntohs() and htons() on non-Windows OS's
#include "stdlib.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "PayloadLayer.h"
#include "UdpLayer.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "PlatformSpecificUtils.h"
#include <time.h>
// #include <unistd.h>
#include <chrono>
#include <thread>

#define LEN 20

float rate_limit = 1.0;
int fbp_cnt = 0;

static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
    
    // parsed the raw packet
    pcpp::Packet parsedPacket(packet);

    pcpp::UdpLayer* udp = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
    if (udp != NULL && ntohs(udp->getUdpHeader()->portSrc) == (uint16_t)12346) {
        rate_limit = 2.0;
        fbp_cnt++;
        // printf("%d\n", ntohs(udp->getUdpHeader()->portSrc));  
    }
}

int main(int argc, char* argv[])
{

    // Packet Creation
    // ~~~~~~~~~~~~~~~
    std::string interfaceIPAddr(argv[1]);
    std::string destAddr(argv[2]);
    
    std::string iface2(interfaceIPAddr);
    iface2[5] = '1';
    // Get device info
    // ~~~~~~~~~~~~~~~
    // find the interface by IP address
    pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr.c_str());
    if (dev == NULL)
    {
        printf("Cannot find interface with IPv4 address of '%s'\n", interfaceIPAddr.c_str());
        exit(1);
    }

    // pcpp::PcapLiveDevice* dev1 = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(iface2.c_str());
    // if (dev1 == NULL)
    // {
    //     printf("Cannot find interface with IPv4 address of '%s'\n", iface2.c_str());
    //     exit(1);
    // }
    
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

    // if (!dev1->open())
    // {
    //     printf("Cannot open device\n");
    //     exit(1);
    // }

    printf("\nStarting pkt creation...\n");

    // create a new Ethernet layer
    int NUMBER_OF_PACKETS = atoi(argv[4]);
    int i = 0;
    clock_t t;
    
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
    newIPLayer.getIPv4Header()->totalLength = htons(28+LEN);
    
    // create a new UDP layer with dummy ports
    pcpp::UdpLayer newUdpLayer(atoi(argv[3]), 12346);
    newUdpLayer.getUdpHeader()->length = htons(8+LEN);

    uint8_t* payload = (uint8_t*)malloc(LEN);
    uint8_t val[LEN];
    for (int i = 0; i < LEN; i++)
        val[i] = 0;
    val[3] = atoi(argv[6]);
    memcpy(payload, val, LEN);
    pcpp::PayloadLayer newPayload(payload, LEN, 0);

    // create a packet with initial capacity of 100 bytes (will grow automatically if needed)
    pcpp::Packet newPacket;

    // add all the layers we created
    newPacket.addLayer(&newEthernetLayer);
    newPacket.addLayer(&newIPLayer);
    newPacket.addLayer(&newUdpLayer);
    newPacket.addLayer(&newPayload);

    // dev1->startCapture(onPacketArrives, NULL);

    // t = clock();
    struct timeval end, start;
    gettimeofday(&start, NULL);

    for (i = 0; i < NUMBER_OF_PACKETS; i++)
    {   
        rate_limit -= (rate_limit - 1.0)*0.02;

        newIPLayer.getIPv4Header()->headerChecksum = htons(i);
        
        // compute all calculated fields
        // newPacket.computeCalculateFields();

        printf("%f\n" , rate_limit);
        std::this_thread::sleep_for(std::chrono::microseconds(atoi(argv[5])) * rate_limit);

        // PCAP_SLEEP(atof(argv[5]));
        
        if (!dev->sendPacket(&newPacket))
        {
            printf("Couldn't send packet\n");
            exit(1);
        }

    }
    gettimeofday(&end, NULL);
    // PCAP_SLEEP(5);  
    // dev1->stopCapture();
    printf("%d packets sent\n", NUMBER_OF_PACKETS);
    long long int time_taken = (end.tv_sec - start.tv_sec)*1000000 + (end.tv_usec - start.tv_usec); // in seconds
    printf("%d\n", fbp_cnt);
    printf("Sending took %lld microseconds \n", time_taken);
}
