

use std::net::UdpSocket;

extern crate snmp_parser;
use snmp_parser::*;

fn handle_v1trap(obj: SnmpMessage) {
    println!("SNMPv1 trap: {:?}", obj);
}

fn handle_v1(obj: SnmpMessage) {
    match obj.pdu_type() {
        PduType::TrapV1 => handle_v1trap(obj),
        _ => {
            println!("Unhandled SNMPv1 PDU type '{:?}'", obj);
            return
        }
    }
}

fn handle_v2trap(obj: SnmpMessage) {
    println!("SNMPv2 trap: {:?}", obj);
}

fn handle_v2(obj: SnmpMessage) {
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

