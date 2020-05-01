#include <in.h> 
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
#include <iostream>
#include <chrono>
#include <thread>
#include "PcapFileDevice.h"

using namespace std;
double replay = 5;

int main(int argc, char* argv[])
{

	// Packet Creation
	// ~~~~~~~~~~~~~~~
    std::string interfaceIPAddr(argv[1]);
    
    // Get device info
    // ~~~~~~~~~~~~~~~
    // find the interface by IP address
    pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr.c_str());
    if (dev == NULL)
    {
        printf("Cannot find interface with IPv4 address of '%s'\n", interfaceIPAddr.c_str());
        exit(1);
    }

    std::string lg_mac = dev->getMacAddress().toString();

    // open the device before start capturing/sending packets
    if (!dev->open())
    {
        printf("Cannot open device\n");
        exit(1);
    }

    // open a pcap file for reading
    pcpp::PcapFileReaderDevice reader("long");
    if (!reader.open())
    {
        printf("Error opening the pcap file\n");
        return -1;
    }

    pcpp::RawPacket rawPacket;
    

    printf("\nStarting pkt creation...\n");

    int ctr = 0;
    long start_time, pkt_time = 0;

    chrono::high_resolution_clock::time_point start;
    chrono::high_resolution_clock::time_point end;
    chrono::duration<double, milli> duration_sec;
    
    while (reader.getNextPacket(rawPacket))
    {
        if (ctr == 0) {
            timespec ts = rawPacket.getPacketTimeStamp();
            start_time = ts.tv_sec * 1e6 + ts.tv_nsec * 1e-3; // microseconds
            start = chrono::high_resolution_clock::now();
        }
        else {
            timespec ts = rawPacket.getPacketTimeStamp();
            pkt_time = ts.tv_sec * 1e6 + ts.tv_nsec * 1e-3 - start_time; // microseconds
            
            end = chrono::high_resolution_clock::now();
            duration_sec = chrono::duration_cast<chrono::duration<double, milli>>(end - start);
            
            int durn = (pkt_time*replay - duration_sec.count()*1e3)-80;
            cout << durn << endl;
            if (durn > 0)
            	std::this_thread::sleep_for(std::chrono::microseconds(durn));
        }
        pcpp::Packet parsedPacket(&rawPacket);
        if (!dev->sendPacket(&parsedPacket))
        {
            printf("Couldn't send packet\n");
            exit(1);
        }

        ctr += 1;

    }

    end = chrono::high_resolution_clock::now();
    duration_sec = chrono::duration_cast<chrono::duration<double, milli>>(end - start);

   	cout << "Total time : " << duration_sec.count() << endl;
    reader.close();
}
