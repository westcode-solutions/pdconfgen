

use std::net::UdpSocket;
use std::str;

extern crate snmp_parser;
use snmp_parser::*;

extern crate der_parser;
use der_parser::*;

/*
alert id="42"
{
    snmp-v1-trap 
    {
      agent-addr value="192.168.2.116";
      enterprise value="1.3.6.1.4.1.1824";
	  generic-trap value="6"; # enterpriseSpecific
      specific-trap value="1";
    }
}
*/

fn handle_v1trap(pdu: SnmpTrapPdu) {
    println!("SNMPv1 trap: {:?}", pdu);

    let id = 42;

    let address = match pdu.agent_addr {
        NetworkAddress::IPv4(adr) => adr
    };

    let generic = match pdu.generic_trap {
        TrapType(val) => val
    };

    println!("");
    println!("alert id=\"{}\"",id);
    println!("{{");    
    println!("\tsnmp-v1-trap");    
    println!("\t{{");

    println!("\t\tagent-addr value=\"{}\";",address);
    println!("\t\tenterprise value=\"{}\";",pdu.enterprise);
    println!("\t\tgeneric-trap value=\"{}\";",generic);
    println!("\t\tspecific-trap value=\"{}\";",pdu.specific_trap);

    for varbind in pdu.var {

        let (data, datatype, comment) = match varbind.val {
            ObjectSyntax::String(data) => {
                (String::from_utf8(data.to_vec()).unwrap(), "OCTET-STRING", "OctetString")
            },
            ObjectSyntax::Counter32(data) => {
                (data.to_string(),"UINT:65","Counter32")
            },
            ObjectSyntax::Gauge32(data) => {
                (data.to_string(),"UINT:66","Gauge32")
            },
            ObjectSyntax::UInteger32(data) => {
                (data.to_string(),"UINT","unsigned integer 32")
            },
            ObjectSyntax::Object(data) => {
                (data.to_string(),"OID","oid")
            },
            ObjectSyntax::IpAddress(data) => {
                let address = match data {
                    NetworkAddress::IPv4(adr) => adr
                };
                (address.to_string(),"IP-ADDRESS","ip address")
            },
            ObjectSyntax::TimeTicks(data) => {
                (data.to_string(),"TIMETICKS","timeticks")
            },
            ObjectSyntax::Number(data) => {
                let val = match data.content {
                    DerObjectContent::Integer(i) => {
                        let mut val:i32 = 0;
                        for byte in i {
                            val = (val << 8) + *byte as i32;
                        }
                        val
                    },
                    _ => 0
                };
                (val.to_string(),"INTEGER","integer")
            },
            _ => (String::from(""),"","") 
        };


        println!("\t\tvarbind var=\"{}\" type=\"{}\" value=\"{}\"; # {}",varbind.oid,datatype,data,comment);
    }

    println!("\t}}");
    println!("}}");
    println!("");
}

/*
Number(DerObject<'a>)
String(&'a [u8])
Object(Oid)
BitString(u8, BitStringObject<'a>)
Empty
UnknownSimple(DerObject<'a>)
IpAddress(NetworkAddress)
Counter32(Counter)
Gauge32(Gauge)
TimeTicks(TimeTicks)
Opaque(&'a [u8])
NsapAddress(&'a [u8])
Counter64(u64)
UInteger32(u32)
UnknownApplication(u8, &'a [u8])
*/

/*
OID ASN.1 BER typ 0x06
STRING ASN.1 BER typ 0x1C
OCTET-STRING ASN.1 BER typ 0x04
INT, INTEGER ASN.1 BER typ 0x02
TIMETICKS, TICKS ASN.1 BER typ 0x43
BOOL, BOOLEAN ASN.1 BER typ 0x01
UINT32, UINT ASN.1 BER typ 0x47
IP, IP-ADDR, IP-ADDRESS ASN.1 BER typ 0x40
*/

fn handle_v1(obj: SnmpMessage) {
    println!("set snmp-community=\"{}\";", obj.community);

    match obj.pdu {
        SnmpPdu::TrapV1(pdu) => handle_v1trap(pdu),
        _ => {
            println!("Unhandled SNMPv1 PDU type '{:?}'", obj);
            return
        }
    }
}

/*
alert id="1042"
{
    snmp-v2-trap 
    {
      varbind var="1.3.6.1.2.1.1.3.0" type="timeticks:67" value="*"; 
      varbind var="1.3.6.1.6.3.1.1.4.1.0" type="OID" value="1.3.6.1.4.1.1824.0.1";            # enterprise
	  varbind var="1.3.6.1.4.1.1824.1.0.0.1" type="OCTET-STRING" value="This is a string";
	  varbind var="1.3.6.1.4.1.1824.1.0.0.1" type="UINT:65" value="3345556"; # Counter
	  varbind var="1.3.6.1.4.1.1824.1.0.0.1" type="UINT:66" value="12343212"; # Gauge
	  varbind var="1.3.6.1.4.1.1824.1.0.0.1" type="INTEGER" value="99";
	  varbind var="1.3.6.1.4.1.1824.1.0.0.1" type="IP-ADDRESS" value="100.200.123.111";
	  varbind var="1.3.6.1.4.1.1824.1.0.0.1" type="OID" value="1.2.3.4.5.6.7.8.9";
	  varbind var="1.3.6.1.4.1.1824.1.0.0.1" type="TIMETICKS" value="2233121";
    }
}
*/

fn handle_v2trap(obj: SnmpMessage) {
    println!("SNMPv2 trap: {:?}", obj);

}

fn handle_v2(obj: SnmpMessage) {
    println!("set snmp-community=\"{}\";", obj.community);

    match obj.pdu_type() {
        PduType::TrapV2 => handle_v2trap(obj),
        _ => {
            println!("Unhandled SNMPv2 PDU type '{:?}'", obj);
            return
        }
    }
}

fn main() {
    let mut socket = match UdpSocket::bind("127.0.0.1:34254") {
        Ok(socket) => socket,
        Err(e) => {
            println!("Failed to open socket. Error: '{}'", e);
            return
        }
    };

    let mut buf = [0; 1500];
    let (amt, src) = match socket.recv_from(&mut buf) {
        Ok(res) => res,
        Err(e) => {
            println!("Failed to read from socket. Error: '{}'", e);
            return
        }
    };
    // "Resize" buf
    let buf = &mut buf[..amt];

    println!("Received data from {}. Length={}", src, buf.len());
    for byte in buf.iter() {
        print!("{:x} ",byte);
    }
    println!("");

    let (rest, obj) = match parse_snmp_generic_message(&buf) {
        Ok((rest, obj)) => (rest, obj),
        Err(e) => {
            println!("Failed to parse object. Error: '{}'", e);
            return
        }
    };

    if rest.len() != 0 {
        println!("Not all data was parsed. Rest: '{}'", rest.len());
        return
    }

    match obj {
        SnmpGenericMessage::V1(obj) => handle_v1(obj),
        SnmpGenericMessage::V2(obj) => handle_v2(obj),
        _ => {
            println!("Unhandled SNMP type '{:?}'", obj);
            return
        }
    };

}

