/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>  TCP_PROTOCOL = 0x06;
const bit<16> TYPE_IPV4 = 0x800;
const bit<19> ECN_THRESHOLD = 10;
const bit<3> TCP_INT = 0x7;                                    # INT flag bit
const bit<16> INT_HEADER_SIZE = 12;
const bit<16> INT_SHIM_HEADER_SIZE = 4;

#define MAX_HOPS 9
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> switchID_t;
typedef bit<32> hop_latency_t;
typedef bit<32> ingress_tstamp_t;
typedef bit<32> egress_tstamp_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   len;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

// INT shim header for TCP
header int_shim_t {
    bit<4> type;
    bit<2> npt;
    bit<2> rsvd1;
    bit<8> len;
    bit<8> rsvd2;
    bit<6> dscp;
    bit<2> rsvd3;
}

header int_header_t {
    bit<4>  ver;
    bit<1>  d;
    bit<1>  e;
    bit<1>  m;
    bit<12> rsvd1;
    bit<5>  hop_metadata_len;
    bit<8>  count;
    bit<16> instruction_mask;
    bit<8>  rsvd2;
}

header int_metadata_t {
    switchID_t    swid;
    hop_latency_t hop_latency;
    ingress_tstamp_t   ingress_tstamp;
    egress_tstamp_t  egress_tstamp;
}

struct ingress_metadata_t {                
    bit<16>  count;                                  //INT switch count
}                                  

struct parser_metadata_t {                            
    bit<16>  remaining;                          //remaining unresolved metadata
}                                            

struct metadata {
    ingress_metadata_t   ingress_metadata;
    parser_metadata_t   parser_metadata;
}

struct headers {
    ethernet_t        ethernet;
    ipv4_t            ipv4;
    tcp_t             tcp;
    int_shim_t        int_shim;
    int_header_t      int_header;
    int_metadata_t[MAX_HOPS]    int_metadata;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TCP_PROTOCOL: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.tcp.res) {
            TCP_INT: parse_int_shim;
            default: accept;
        }
    }

    state parse_int_shim {
        packet.extract(hdr.int_shim);
        transition parse_int_header;
    }

    state parse_int_header {
        packet.extract(hdr.int_header);
        meta.parser_metadata.remaining = 4;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_int_metadata;
            }
    }
    
    state parse_int_metadata{
        packet.extract(hdr.int_metadata.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining  - 1;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_int_metadata;
            }
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        /*size = 1024;*/
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action mark_ecn() {
        hdr.ipv4.ecn = 3;
        hdr.ipv4.dscp = 0x17;
        hdr.tcp.res = 7;
        hdr.int_shim.setValid();
    }

\\ Modifying intshim
    action xg_intshim(){
        hdr.int_shim.type = 1;
        hdr.int_shim.len = (bit<8>)INT_HEADER_SIZE; 
        hdr.int_shim.dscp = hdr.ipv4.dscp;
        hdr.int_header.setValid();
    }

\\ Modifying int
    action xg_int(){
        hdr.int_header.ver = 2;
        hdr.int_header.d = 0;
        hdr.int_header.e = 0;
        hdr.int_header.m = 0;
        hdr.int_header.instruction_mask =0b110101;
        hdr.int_header.rsvd1 = 0;
        hdr.int_header.rsvd2 = 0;
        hdr.ipv4.len = hdr.ipv4.len + INT_HEADER_SIZE + INT_SHIM_HEADER_SIZE;
    }

    action add_metadata(switchID_t swid){
        hdr.int_header.count = hdr.int_header.count+1;
        hdr.int_metadata.push_front(1);     
        hdr.int_metadata[0].setValid();
        hdr.int_metadata[0].swid = swid;
        hdr.int_metadata[0].hop_latency = (bit<32>) standard_metadata.egress_global_timestamp - (bit<32>) standard_metadata.ingress_global_timestamp;
        hdr.int_metadata[0].ingress_tstamp = (bit<32>) standard_metadata.ingress_global_timestamp;
        hdr.int_metadata[0].egress_tstamp = (bit<32>) standard_metadata.egress_global_timestamp;
        
        hdr.int_shim.len =  (bit<8>)(INT_HEADER_SIZE+ 16);
        hdr.int_header.hop_metadata_len = hdr.int_header.hop_metadata_len + 16;
        hdr.ipv4.len = hdr.ipv4.len + 16;  
    }
    
    table swtrace {
        actions = { 
	    add_metadata; 
	    NoAction; 
        }
        default_action = NoAction();      
    }


/*    action instruction_mark_0(switchID_t swid){//switch_id
        hdr.int_metadata.push_front(1);     
        hdr.int_metadata[0].setValid();
        hdr.int_metadata[0].swid = swid;
    }

    action instruction_mark_2(){//hop_latency
        hdr.int_metadata.push_front(1);     
        hdr.int_metadata[0].setValid();
        hdr.int_metadata[0].hop_latency = (bit<32>) standard_metadata.egress_global_timestamp - (bit<32>) standard_metadata.ingress_global_timestamp;
    }

    action instruction_mark_4(){//Ingress timestamp
        hdr.int_metadata.push_front(1);     
        hdr.int_metadata[0].setValid();
        hdr.int_metadata[0].ingress_tstamp = (bit<32>) standard_metadata.ingress_global_timestamp;
    }
    
    action instruction_mark_5(){//egress timestamp
        hdr.int_metadata.push_front(1);     
        hdr.int_metadata[0].setValid();        
        hdr.int_metadata[0].egress_tstamp = (bit<32>) standard_metadata.egress_global_timestamp;
    }


    table swtrace {
        key = {
            hdr.int_header.instruction_mask: exact;
        }
        actions = {
            instruction_mark_0();
            instruction_mark_2();
            instruction_mark_4();
            instruction_mark_5();
            NoAction;
        }
        const entries = {
            (0x0) : instruction_mark_0();
            (0x2) : instruction_mark_2();
            (0x8) : instruction_mark_4();
            (0x10) : instruction_mark_5();
        }
        default_action = NoAction();
    } */


    apply {
        if (hdr.ipv4.ecn == 1 || hdr.ipv4.ecn == 2){
            if (standard_metadata.enq_qdepth >= ECN_THRESHOLD){
                mark_ecn();
            }
            if(hdr.int_shim.isValid()){
               xg_intshim();  
               xg_int();         
            }
            if(hdr.int_header.isValid()){
               swtrace.apply();                       
            }
         }                  
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
	      hdr.ipv4.dscp,
	      hdr.ipv4.ecn,
              hdr.ipv4.len,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

	update_checksum(
	    hdr.tcp.isValid(),
            { hdr.tcp.src_port,
	      hdr.tcp.dst_port,
	      hdr.tcp.seq_no,
	      hdr.tcp.ack_no,
	      hdr.tcp.data_offset,
	      hdr.tcp.res,
	      hdr.tcp.flags,
	      hdr.tcp.window,
	      hdr.tcp.urgent_ptr },
	    hdr.tcp.checksum,
	    HashAlgorithm.csum16);
     }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.int_shim);
        packet.emit(hdr.int_header);
        packet.emit(hdr.int_metadata);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;




