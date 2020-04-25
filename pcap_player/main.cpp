#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "IcmpLayer.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include <iostream>
#include <pthread.h>
#include <semaphore.h>
#include <queue>
#include <chrono>
#include <ratio>

using namespace std;

queue<pcpp::RawPacket> q;
sem_t full;
pthread_mutex_t mutex;
bool stop = false;

void* produce(void* arg) {

    chrono::high_resolution_clock::time_point start;
    chrono::high_resolution_clock::time_point end;
    chrono::duration<double, milli> duration_sec;
    
    // open a pcap file for reading
    pcpp::PcapFileReaderDevice reader("../cms/univ1_trace/ap_00000_20091217102604");
    if (!reader.open())
    {
        printf("Error opening the pcap file\n");
        return (void*)1;
    }

    pcpp::RawPacket rawPacket;
    int ctr = 0;
    while (reader.getNextPacket(rawPacket))
    {
        start = chrono::high_resolution_clock::now();
        pthread_mutex_lock(&mutex);
        q.push(rawPacket);
        pthread_mutex_unlock(&mutex);
        sem_post(&full);

        



        ctr++;
        // cout << ctr << endl;

        end = chrono::high_resolution_clock::now();
        duration_sec = chrono::duration_cast<chrono::duration<double, milli>>(end - start);

        // cout << duration_sec.count() << endl;
    
    }

    stop = true;
    // close the file
    reader.close();
        
    
}

void* consume(void* arg){
    pcpp::RawPacket rawPacket;
    pcpp::IPv4Address srcIP("1.2.3.4"), destIP("5.6.7.8");
    uint16_t srcPort = 1234, dstPort = 5678;
    uint8_t protocol = 10;

    while(1) {
        
        sem_wait(&full); // wiait until queue has something
        pthread_mutex_lock(&mutex);
        // cout << q.size() << endl;
        rawPacket = q.front();
        q.pop();
        pthread_mutex_unlock(&mutex);

        // parse the raw packet into a parsed packet
        pcpp::Packet parsedPacket(&rawPacket);
        cout << rawPacket.getRawDataLen() << endl;

        // check if packet is of type IPv4
        if (parsedPacket.isPacketOfType(pcpp::IPv4))
        {
            // extract source and dest IPs
            srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress();
            destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress();
            protocol = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getProtocol();
            if (protocol == (uint8_t)6) {
                srcPort = parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->portSrc;
                dstPort = parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->portSrc;
            }

            if (protocol == (uint8_t)17) {
                srcPort = parsedPacket.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portSrc;
                dstPort = parsedPacket.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portDst;
            }

            // print source and dest IPs
            printf("Source IP is '%s'; Dest IP is '%s'\n", srcIP.toString().c_str(), destIP.toString().c_str());
        }

        // Put all other ARP / ICMP packets in the same flow class


        if (stop && q.size() == 0)
            break;        
        
    }
}


int main(int argc, char* argv[])
{
    pthread_t producer,consumer;
    sem_init(&full, 0, 0);
    pthread_mutex_init(&mutex, NULL);
    pthread_create(&producer, NULL, produce, NULL);
    pthread_create(&consumer, NULL, consume, NULL);

    pthread_join(producer, NULL);
    // pthread_join(consumer, NULL);
    
    cout << "Exiting!!\n";

    
    return 0;
}