#include <core.p4>
#include <v1model.p4>

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8> PROTO_UDP = 17;
const bit<8> PROTO_TCP = 0x06;

// Ethernet L2 header
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

// IP L3 header
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    diffserv; // now is simply DSCP (not tos)
    bit<2>    ecn;  // borrowing 2 bits from diffserv
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// UDP L4 header
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}


struct metadata {
    bit<32> idx1;
    bit<32> idx2;
    bit<32> idx3;
    bit<32> idx4;
    bit<32> idx5;
    bit<32> idx6;
    bit<32> idx7;
    bit<32> idx8;

    bit<32> val1;
    bit<32> val2;
    bit<32> val3;
    bit<32> val4;
    bit<32> val5;
    bit<32> val6;
    bit<32> val7;
    bit<32> val8;

    bit<32> ws;    
}

// Plain UDP packets
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    udp_t      udp;
}