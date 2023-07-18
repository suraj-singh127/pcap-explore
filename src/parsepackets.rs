use pktparse::{*, tcp::TcpHeader, udp::UdpHeader, ipv4::IPv4Header, ipv6::IPv6Header, arp::ArpPacket};
use pktparse::ip::IPProtocol;
use pktparse::ethernet::{EtherType,EthernetFrame};
use tls_parser::TlsMessage;

//Enumeration for headers of different header types
#[derive(Debug)]
pub enum PacketHeader {
    Arp(ArpPacket),
    Tcp(TcpHeader),
    UDP(UdpHeader),
    IPv4(IPv4Header),
    IPv6(IPv6Header),
    Tls(TlsType),
    Ether(EthernetFrame),
}

//For specifying the type of tls message
#[derive(Debug)]
pub enum TlsType {
    Handshake,
    ChangeCipherSpec,
    Alert,
    ApplicationData,
    Heartbeat,
    EncryptedData,
}

//Convert PacketHeader type to String
impl ToString for PacketHeader{
    fn to_string(&self) -> String {
        match self {
            PacketHeader::Arp(_) => String::from("Arp"),
            PacketHeader::IPv4(_) => String::from("IPv4"),
            PacketHeader::IPv6(_) => String::from("IPv6"),
            PacketHeader::Tcp(_) => String::from("TCP"),
            PacketHeader::UDP(_) => String::from("UDP"),
            PacketHeader::Tls(_) => String::from("TLS"),
            PacketHeader::Ether(_) => String::from("Ether")
        }
    }
}

//Parsed Packet struct with -
//len - length of the parsed packet
//timestamp - Time at which the packet was captured
//headers - header information
//remaining - whatever remains unparsed
#[derive(Debug)]
pub struct ParsedPacket {
    pub len: u32,
    pub timestamp: String,
    pub headers: Vec<PacketHeader>,
    pub remaining: Vec<u8>,
}

//Implementing various functionalities of a parsed packet
impl ParsedPacket{

    //To create a new instance of Parsed Packet
    pub fn new() -> ParsedPacket {
        ParsedPacket { 
            len: 0, 
            timestamp: "".to_string(), 
            headers: vec![], 
            remaining: vec![] 
        }
    }

    //Function for parsing packets 
    //Returns a Result Type - 
    //ParsedPacket - if the packet is parsed without error
    //String - Error string if error is encountered
    pub fn parse_packet(&self,data:Vec<u8>,len:u32,ts:String)
    -> Result<ParsedPacket,String>
    {
        //parsing link layer
        let mut parsed_packet = self.link_layer(&data)?;
        parsed_packet.len = len;
        parsed_packet.timestamp = ts;
        Ok(parsed_packet) //Returning parsed packet
    }

    pub fn link_layer(&self,content:&[u8]) -> Result<ParsedPacket, String> {
        let mut parsed_packet = ParsedPacket::new();

        //Matching ethernet frame to the ethertype ipv4 or ipv6 used
        match ethernet::parse_ethernet_frame(content) {
            Ok((content,headers)) => {
                match headers.ethertype {
                   //if ethertype is ipv4
                   EtherType::IPv4 => {
                        self.parsing_ipv4(content, &mut parsed_packet)?;
                   }
                   //if ethertype is ipv6
                   EtherType::IPv6 => {
                        self.parsing_ipv6(content, &mut parsed_packet)?;
                   }
                   //if ethertype is arp
                   EtherType::ARP => {
                        self.parsing_arp(content, &mut parsed_packet)?;
                   }
                   _ => {
                    //creating a copy of the content remaining and assigning it to the remaining packets
                     parsed_packet.remaining = content.to_owned();
                   }
                }
                //pushing the header information
                parsed_packet.headers.push(PacketHeader::Ether(headers));
            }
            Err(_) => {
                //remaining unparsed packets to be copied
                parsed_packet.remaining = content.to_owned();
            }    
        }

        //Return the parsed packets
        Ok(parsed_packet)
    }

    pub fn parsing_ipv4(&self,content:&[u8],parsed_packet:&mut ParsedPacket)
    -> Result<(),String>
    {
        match ipv4::parse_ipv4_header(content) {

            Ok((content,header)) => {
                //parsing transport layer
                self.parsing_transport_layer(&header.protocol, content, parsed_packet)?;

                //push the header info
                parsed_packet.headers.push(PacketHeader::IPv4(header));

                //Return
                Ok(())
            }

            Err(e) => {
                //remaining bytes
                parsed_packet.remaining = content.to_owned();

                //return the error if encountered
                Err(e.to_string())
            }
        }
    }

    pub fn parsing_ipv6(&self,content:&[u8],parsed_packet:&mut ParsedPacket)
    -> Result<(),String>
    {   
        //Parsing IPv6 header
        match ipv6::parse_ipv6_header(content) {
            Ok((content,headers)) => {
                //Parsing transport layer for getting the IPv6 header
                self.parsing_transport_layer(&headers.next_header, content, parsed_packet).expect("Error Parsing Transport Layer");

                //pushing the header information to parsed packet header information
                parsed_packet.headers.push(PacketHeader::IPv6(headers));
                Ok(())
            },
            Err(e) => {
                //remaining bytes
                parsed_packet.remaining = content.to_owned();
                Err(e.to_string())
            }
        }

    }

    pub fn parsing_arp(&self,content:&[u8],parsed_packet:&mut ParsedPacket)
    -> Result<(), String>
    {
        //Parsing ARP header
        match arp::parse_arp_pkt(content) {

            Ok((_content, headers)) => {
                //pushing header information to packet header info
                parsed_packet.headers.push(PacketHeader::Arp(headers));
                Ok(())
            }

            Err(err) => {
                //add the not parsed bytes to remaining
                parsed_packet.remaining = content.to_owned();
                Err(err.to_string())
            }
        }
    }

    pub fn parsing_transport_layer(&self,protocol:&ip::IPProtocol,content:&[u8],parsed_packet:&mut ParsedPacket)
    -> Result<(),String>
    {   //Parsing transport layer by identifying the transport layer protocol
        //It is done by matching the IPProtocol to either TCP or UDP
        match protocol{

            //Matching UDP
            IPProtocol::UDP => {
                self.parsing_udp(content, parsed_packet).expect("Error Parsing UDP");
                Ok(())      
            }

            //Matchin TCP
            IPProtocol::TCP => {
                self.parsing_tcp(content, parsed_packet).expect("Error Parsing TCP");
                Ok(())
            }

            //If its neither TCP nor UDP
            _ => {
                parsed_packet.remaining = content.to_owned();
                Err("Not TCP and UDP".to_string()) 
            }   
        }
    }

    //for parsing tcp packets
    pub fn parsing_tcp(&self,content:&[u8],parsed_packet:&mut ParsedPacket)
    -> Result<(),String>
    {
        //Parsing the TCP header information
        match tcp::parse_tcp_header(content) {
            Ok((content,header)) => {
                //Parsing TLS on top of TCP 
                self.parsing_tls(content, parsed_packet);

                //Then pushing TCP header information to Parsed Packet header info
                parsed_packet.headers.push(PacketHeader::Tcp(header));
                Ok(())
            }
            Err(e) => {
                //adding the remaining bytes
                parsed_packet.remaining = content.to_owned();
                Err(e.to_string())
            }
        }
    }

    //For parsing UDP header
    pub fn parsing_udp(&self,content:&[u8],parsed_packet:&mut ParsedPacket)
    -> Result<(), String>
    {
        //Parsing the UDP Header
        match udp::parse_udp_header(content) {
            Ok((content,header)) => {
                //Parsing the TLS Protocol on top of UDP
                self.parsing_tls(content, parsed_packet);

                //Pushing the header information to Packet Header information
                parsed_packet.headers.push(PacketHeader::UDP(header));
                Ok(())
            }
            Err(e) => {
                //remaining bytes
                parsed_packet.remaining = content.to_owned();
                Err(e.to_string())
            }
        }
    }

    //function for parsing tls
    pub fn parsing_tls(&self,content:&[u8],parsed_packet:&mut ParsedPacket){
        //Parsing TLS
        //parse_tls_plaintext parses a single packet and returns the content and TLSPlaintext
        //TLSPlaintext contains TLSRecordHeader and a vector of messages  
        if let Ok((_content,headers)) = tls_parser::parse_tls_plaintext(content){
            //Matching enum TLS Messages to different types of messages 
            if let Some(msg) = headers.msg.get(0) {
                match msg {
                    //Handshake
                    TlsMessage::Handshake(_) => {
                        parsed_packet.headers.push(PacketHeader::Tls(TlsType::Handshake));
                    },
                    //For app data only after handshake has been performed
                    TlsMessage::ApplicationData(app_data) => {
                        parsed_packet.headers.push(PacketHeader::Tls(TlsType::ApplicationData));
                        parsed_packet.remaining = app_data.blob.to_owned();
                    },
                    //Changing Cipher spec
                    TlsMessage::ChangeCipherSpec => {
                        parsed_packet.headers.push(PacketHeader::Tls(TlsType::ChangeCipherSpec));
                    },
                    //
                    TlsMessage::Heartbeat(_) => {
                        parsed_packet.headers.push(PacketHeader::Tls(TlsType::Heartbeat));
                    },
                    //
                    TlsMessage::Alert(_) => {
                        parsed_packet.headers.push(PacketHeader::Tls(TlsType::Alert));
                    }
                }
            }
            else if let Ok((_content,_headers)) = tls_parser::parse_tls_plaintext(content) {
                //push the header information to header info
                parsed_packet.headers.push(PacketHeader::Tls(TlsType::EncryptedData));
            }
            else{
                //remaining bytes
                parsed_packet.remaining = content.to_owned();
            }
        }
    }

}