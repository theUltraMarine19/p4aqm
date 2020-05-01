#include <core.p4>
#include <v1model.p4>

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const bit<16> TYPE_VLAN = 0x8100;
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
header vlan_t {
    bit<3> priority;
    bit<1> dei;
    bit<12> vlanid;
    bit<16> tpid;
}

struct metadata {
    // empty
}

struct headers {
    ethernet_t ethernet;
    vlan_t vlan;
    ipv4_t     ipv4;
}