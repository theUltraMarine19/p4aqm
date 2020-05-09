#include <core.p4>
#include <v1model.p4>
#include "headers_test.p4"
#include "parser_test.p4"

typedef bit<9>  egressSpec_t;
const bit<32> E2E_CLONE_SESSION_ID_H1 = 500;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE = 2;

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

	// action no_op() {}

	// table dummy1 {
	// 	key = { hdr.ethernet.dstAddr : exact; }
	// 	actions = { no_op;}
	// }
	// table dummy2 {
	// 	key = { hdr.ethernet.dstAddr : exact; }
	// 	actions = { no_op;}
	// }
	// table dummy3 {
	// 	key = { hdr.ethernet.dstAddr : exact; }
	// 	actions = { no_op;}
	// }
	// table dummy4 {
	// 	key = { hdr.ethernet.dstAddr : exact; }
	// 	actions = { no_op;}
	// }
	// table dummy5 {
	// 	key = { hdr.ethernet.dstAddr : exact; }
	// 	actions = { no_op;}
	// }
	// table dummy6 {
	// 	key = { hdr.ethernet.dstAddr : exact; }
	// 	actions = { no_op;}
	// }
	// table dummy7 {
	// 	key = { hdr.ethernet.dstAddr : exact; }
	// 	actions = { no_op;}
	// }
	// table dummy8 {
	// 	key = { hdr.ethernet.dstAddr : exact; }
	// 	actions = { no_op;}
	// }
	// table dummy9 {
	// 	key = { hdr.ethernet.dstAddr : exact; }
	// 	actions = { no_op;}
	// }
	// table dummy10 {
	// 	key = { hdr.ethernet.dstAddr : exact; }
	// 	actions = { no_op;}
	// }
	


	apply {
		standard_metadata.egress_spec = 2;
		// hdr.ethernet.etherType = 16w69;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
		// dummy1.apply();
		// dummy2.apply();
		// dummy3.apply();
		// dummy4.apply();
		// dummy5.apply();
		// dummy6.apply();
		// dummy7.apply();
		// dummy8.apply();
		// dummy9.apply();
		// dummy10.apply();
			
	}

}


// No checksum verification
control vrfy(inout headers h, inout metadata meta) { apply {} }

// No checksum update
control updt(inout headers h, inout metadata meta) { apply {} }

// No per-port specific modification in egress
control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) { 
	
	apply {

		hdr.vlan.vlanid = (bit<12>)standard_metadata.deq_timedelta;
		// hdr.debug.ws = (bit<32>)standard_metadata.enq_qdepth;
	} 
}	

V1Switch(c_parser(), vrfy(), ingress(), egress(), updt(), c_deparser()) main;