

use std::net::UdpSocket;
use std::str;

extern crate snmp_parser;
use snmp_parser::*;

extern crate der_parser;
use der_parser::*;

extern crate clap;
use clap::{Arg, App};

/*
PD Sentry SNMPv1 Syntax:

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

fn handle_varbinds(vars: Vec<SnmpVariable<>>) {
    for varbind in vars {

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
                    DerObjectContent::Integer(int) => {
                        if int.len() > 4 {
                            println!("Integer too long '{:?}'", int);
                            return
                        }
                        let mut tmp:i32 = int[0] as i8 as i32;
                        for idx in 1..int.len() {
                            tmp = (tmp << 8) | (int[idx] as i32)
                        }
                        tmp
                    },
                    _ => {
                        println!("Unhandled number '{:?}'", data.content);
                        return
                    }
                };
                (val.to_string(),"INTEGER","integer")
            },
            _ => (String::from(""),"","") 
        };


        println!("\t\tvarbind var=\"{}\" type=\"{}\" value=\"{}\"; # {}",varbind.oid,datatype,data,comment);
    }
}

fn handle_v1trap(pdu: SnmpTrapPdu, id: u32) {

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

    handle_varbinds(pdu.var);

    println!("\t}}");
    println!("}}");
    println!("");
}

/*
From rust snmp-parser:

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
From PD Sentry documentation:

OID ASN.1 BER typ 0x06
STRING ASN.1 BER typ 0x1C
OCTET-STRING ASN.1 BER typ 0x04
INT, INTEGER ASN.1 BER typ 0x02
TIMETICKS, TICKS ASN.1 BER typ 0x43
BOOL, BOOLEAN ASN.1 BER typ 0x01
UINT32, UINT ASN.1 BER typ 0x47
IP, IP-ADDR, IP-ADDRESS ASN.1 BER typ 0x40
*/

fn handle_v1(obj: SnmpMessage, id: u32) {
    println!("set snmp-community=\"{}\";", obj.community);

    match obj.pdu {
        SnmpPdu::TrapV1(pdu) => handle_v1trap(pdu, id),
        _ => {
            println!("Unhandled SNMPv1 PDU type '{:?}'", obj);
            return
        }
    }
}

/*
PD Sentry SNMPv2 syntax:

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

fn handle_v2trap(pdu: SnmpGenericPdu, id: u32) {
    println!("");
    println!("alert id=\"{}\"",id);
    println!("{{");    
    println!("\tsnmp-v2-trap");    
    println!("\t{{");

    handle_varbinds(pdu.var);

    println!("\t}}");
    println!("}}");
    println!("");
}

fn handle_v2(obj: SnmpMessage, id: u32) {
    if obj.pdu_type() != PduType::TrapV2 {
        println!("Unhandled SNMPv2 PDU type '{:?}'", obj);
        return
    }

    println!("set snmp-community=\"{}\";", obj.community);


    match obj.pdu {
        SnmpPdu::Generic(pdu) => handle_v2trap(pdu, id),
        _ => {
            println!("Unhandled SNMPv2 PDU type '{:?}'", obj);
            return
        }
    }
}

fn main() {
    let default_addr = "127.0.0.1:34254";

    let matches = App::new("PD Sentry Configuration Generator")
                          .version("0.0.1")
                          .author("Mathias Olsson <mathias.olsson@westcode.se>")
                          .about("Generates sample configuration for PD Sentry from SNMP traps")
                          .arg(Arg::with_name("listen")
                               .short("l")
                               .long("listen-address")
                               .help(&format!("IP address and port to listen to. Default {}",default_addr))
                               .takes_value(true))
                          .arg(Arg::with_name("verbose")
                               .short("v")
                               .long("verbose")
                               .help("Sets the level of verbosity"))
                          .get_matches();

    let addr = matches.value_of("listen").unwrap_or(default_addr);
    let verbose = matches.is_present("verbose");

    let socket = match UdpSocket::bind(addr) {
        Ok(socket) => socket,
        Err(e) => {
            println!("Failed to open socket. Error: '{}'", e);
            return
        }
    };

    let mut id = 0;

    loop {
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

        if verbose {
            println!("Received data from {}. Length={}", src, buf.len());
            for byte in buf.iter() {
                print!("{:x} ",byte);
            }
            println!("");
        }

        let (rest, obj) = match parse_snmp_generic_message(&buf) {
            Ok((rest, obj)) => (rest, obj),
            Err(e) => {
                println!("Failed to parse object. Error: '{}'", e);
                return
            }
        };

        if verbose {
            println!("SNMP: {:#?}", obj);
        }

        if rest.len() != 0 {
            println!("Not all data was parsed. Rest: '{}'", rest.len());
            return
        }

        match obj {
            SnmpGenericMessage::V1(obj) => handle_v1(obj, id),
            SnmpGenericMessage::V2(obj) => handle_v2(obj, id),
            _ => {
                println!("Unhandled SNMP type '{:?}'", obj);
                return
            }
        };

        id += 1;
    }
}

