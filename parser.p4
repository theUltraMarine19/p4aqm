parser c_parser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            // default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_UDP: parse_udp; /* PROTO_UDP is 17 */
            default: accept; /* ditch other packets for now */
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        packet.extract(hdr.debug);
        transition accept;
    }
    // Accept all UDP pkts for now

}

control c_deparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.debug);
    }
}
