#include <core.p4>
#include <v1model.p4>
#include "headers_test.p4"
#include "parser_test.p4"

typedef bit<9>  egressSpec_t;
const bit<32> E2E_CLONE_SESSION_ID_H1 = 500;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE = 2;

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

	apply {
		standard_metadata.egress_spec = 3;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;	
	}

}


// No checksum verification
control vrfy(inout headers h, inout metadata meta) { apply {} }

// No checksum update
control updt(inout headers h, inout metadata meta) { apply {} }

// No per-port specific modification in egress
control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) { 
	
	apply {

		if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE) {
			// Mark for ECN
			hdr.ipv4.ecn = 3;
			hdr.ipv4.diffserv = (bit<6>)standard_metadata.enq_qdepth; // Queue length at enqueue
			// Not using queueing delay yet	
		}
		
		else {

			clone3(CloneType.E2E, E2E_CLONE_SESSION_ID_H1, {standard_metadata}); // clone the pkt	
		}		
	} 
}	

V1Switch(c_parser(), vrfy(), ingress(), egress(), updt(), c_deparser()) main;