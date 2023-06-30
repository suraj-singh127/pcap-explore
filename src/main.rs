use pcap::{Device, Capture};
use pktparse::{*, tcp::TcpHeader, udp::UdpHeader, ipv4::IPv4Header, ipv6::IPv6Header, arp::ArpPacket, ethernet::{EtherType, EthernetFrame, MacAddress}, ip::IPProtocol};
use tls_parser::{TlsMessage, nom::{AsBytes}};
use clap::{Parser};


fn main() {

    #[derive(Parser)]
    #[command(name = "sniffit")]
    #[command(version = "1.0")]
    #[command(about = "Capturing packets from interface.")]

    //Struct for parsing the arguments
    pub struct Cli{
        arg1 : Option<String>,
        arg2 : Option<String>,
        arg3 : Option<String>,
    }

    pub struct CapturePacket {
        err_count: u64,
    }

    //Implementing the CapturePacket struct
    impl CapturePacket {
        pub fn new() -> CapturePacket {
            CapturePacket { err_count: 0 }
        }
        
        pub fn print_devices(&self) {
            //Get the list of interface devices found in the form of Result type
            let list = Device::list();

            println!("\n====================================================");
            //print the  list of devices found
            print!("List of Devices found - \n\n");
            let mut serial = 1;
            match list {
                //if the devices are found
                Ok(devices) => {
                    for device in devices {
                        print!("{} Device ID - {}\n",serial, device.name);
                        //matching device desc option string
                        match device.desc {
                            //if there is device description
                            Some(desc) => println!("Description - {}", desc),
                            //No description availaible
                            None => println!("Description not available"),
                        }
                        serial = serial + 1;
                        println!()
                    }
                }
                //if an error occurs
                Err(error) => println!("Error: {}", error),
            }
            println!("\n=======================================================");
            println!("To capture packets from a device - cargo run capture [device_serial number]");
        }

        //Takes the serial number of the device in form of unsigned 8 bit unsigned integer 0-255
        pub fn print_to_console(&self , device_number:u8) {

            let mut device_name = String::from("");
            let mut device_description = "".to_string();

            //Looking for all the interfaces on the devices
            //Device::list() -> Returns a Result<T,E> type where -
            //T - Vector of Devices
            //E - Returns error if encountered
            let list = Device::list();

            //for device selection
            let mut serial = 1;

            //Matching the list to look for the serial number passed as an argument
            match list {
                //Vector of devices
                Ok(devices) => {
                    //Device name of zeroth interface
                    device_name = devices[0].name.clone();

                    //Device desc of first device if there is some description
                    device_description = match &devices[0].desc {
                        Some(desc) => {
                            desc.to_string()
                        }
                        None => "Not Available".to_string()
                    };

                    //Matching the arguments device serial number with actual device
                    for device in devices {

                        //if the serial number matches store the device name and device description
                        if serial == device_number {
                            device_name = device.name;
                            device_description = device.desc.unwrap_or(String::from("Device name not available"));
                        }
                        serial = serial + 1;
                    }
                }
                //Else if error is encountered
                Err(err) => {
                    eprintln!("{:?}",err);
                }
            }
            
            //First a Capture<Inactive> handle is opened by passing the device or device name to Capture::from_device - pcap rust docs
            let cap2 = Capture::from_device(device_name.as_str()).expect("error capturing");
            
            //Then the Capture<Inactive> is activated via .open() function and setting other configurations 
            let mut cap_handle = cap2.promisc(true).snaplen(100).timeout(10000).open().unwrap();

            //Once the device ready for Active Capturing we can list datalinks and use them accordingly
            let data_links = cap_handle.list_datalinks().expect("could not find");
            let symbol = "*";
            let width = 500;
            println!("\n===========================================================================================");
            println!("Links Available are - ");
            for links in data_links{
                println!("{:?}",links.get_description().unwrap());
            }
            println!("\n===========================================================================================");
            println!("Capturing packets from - {}" ,device_description);
            
            //For counting the number of packets
            let mut packet_no:i64 = 1;

            //Now we can traverse over the captured packets by calling active capture handles .next() function            
            while let Ok(packet) = cap_handle.next() {
                let data = packet.data.to_owned();
                let len = packet.header.len;

                //Formaitng the timestamps to be shown upto 6 digit of decimal 
                let ts: String = format!(
                    "{}.{:06}",
                    &packet.header.ts.tv_sec, &packet.header.ts.tv_usec
                );

                //Creating a new instance of Parsed Packet
                let packet_parse = ParsedPacket::new();
                let parsed_packet = packet_parse.parse_packet(data, len, ts);
                self.print_packet(parsed_packet,packet_no);
                packet_no = packet_no + 1;
            }
        }

        //Printing individual packets to console
        pub fn print_packet(&self,parsed_packet:Result<ParsedPacket,String>,packet_no:i64){
            println!("\n===========================================================================================\n");
            
            print!("\n==================================== Packet no. {} =======================================\n\n",packet_no);
            
            match parsed_packet {
                Ok(parsed_packet) => {
                    //parsed packet is passed to function for printing header info
                   &self.header_information(parsed_packet);
                }
                Err(er)=> {
                    eprintln!("{}",er);
                }
            }
            println!("\n===========================================================================================");
        }

        //Function for getting the header information from parsed packet
        pub fn header_information(&self,packet:ParsedPacket) {
            print!("\n============================== Timestamp - {} ==============================\n\n",packet.timestamp);

            for header in packet.headers {
                match header {
                    //Defining action for EthernetFrame header
                    PacketHeader::Ether(ethernet_frame) => {
                        let src = format!("{:02X?}",ethernet_frame.source_mac.0.as_bytes());
                        let dst = format!("{:02X?}",ethernet_frame.dest_mac.0.as_bytes());
                        println!("Source MAC: {}  -----> Destination MAC: {}",&src,&dst);
                    }

                    //For TLS Messages
                    PacketHeader::Tls(tls_message) => {
                        println!("TLS Message type - {:?}",tls_message);
                    }
                    
                    //For IPv4
                    PacketHeader::IPv4(ipv4_header) => {
                        println!("Version - {}  IHL - {}",ipv4_header.version,ipv4_header.ihl);
                        println!("Length - {}   Protocol - {:?}", ipv4_header.length,ipv4_header.protocol);
                        println!("Source Address: {}  -----> Destination Address: {}",ipv4_header.source_addr,ipv4_header.dest_addr);
                    }

                    //for IPv6
                    PacketHeader::IPv6(ipv6_header)=> {
                        
                        println!("Version - {}  Hop Limit - {}", ipv6_header.version,ipv6_header.hop_limit);
                        println!("Length - {}   Protocol - {:?}", ipv6_header.length,ipv6_header.next_header);
                        println!("Source Address: {}  -----> Destination Address: {}",ipv6_header.source_addr,ipv6_header.dest_addr);
                    }

                    //For Arp header - if the packet uses ARP protocol
                    PacketHeader::Arp(arp_packet)=> {
                        
                        println!("Hardware Addr Type:{}   Protocol Address Type:{:?}", arp_packet.hw_addr_size,arp_packet.proto_addr_type);
                        println!("Operation: {:?}",arp_packet.operation);
                        println!("Source MAC: {:?}  -----> Destination MAC: {:?}",arp_packet.src_mac,arp_packet.dest_mac);
                    }

                    //For printing TCP Header information
                    PacketHeader::Tcp(tcp_header) => {
                        
                        println!("Source Port: {} -----> Dest Port: {}",tcp_header.source_port,tcp_header.dest_port);
                        println!("Sequence No: {}   Ack No: {}",tcp_header.sequence_no,tcp_header.ack_no);
                        println!("FLAGS -   ACK: {}   FIN: {}   PSH: {}    RST: {}    SYN: {}   URG:{}",
                        &self.convert_flag(tcp_header.flag_ack),&self.convert_flag(tcp_header.flag_fin),
                        &self.convert_flag(tcp_header.flag_psh),&self.convert_flag(tcp_header.flag_rst),
                        &self.convert_flag(tcp_header.flag_syn),&self.convert_flag(tcp_header.flag_urg));
                        
                    }

                    //For printing UDP Header information
                    PacketHeader::UDP(udp_header) => {
                        println!("Source Port: {} -----> Dest Port: {}",udp_header.source_port,udp_header.dest_port);
                        println!("Length: {}    Checksum: {}",udp_header.length,udp_header.checksum);
                    }
                }
            }
        }
        
        //For converting bool flag to 0 and 1
        pub fn convert_flag(&self,flag:bool) -> u8{
            flag as u8
        }
        
    }
    
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

        pub fn link_layer(&self,content:&[u8])
         -> Result<ParsedPacket, String> {
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
                    self.parsing_transport_layer(&headers.next_header, content, parsed_packet);

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
                    self.parsing_udp(content, parsed_packet);
                    Ok(())      
                }
                //Matchin TCP
                IPProtocol::TCP => {
                    self.parsing_tcp(content, parsed_packet);
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
                        TlsMessage::Heartbeat(_) => {
                            parsed_packet.headers.push(PacketHeader::Tls(TlsType::Heartbeat));
                        },
                        TlsMessage::Alert(_) => {
                            parsed_packet.headers.push(PacketHeader::Tls(TlsType::Alert));
                        }
                    }
                }
                else if let Ok((_content,headers)) = tls_parser::parse_tls_plaintext(content) {
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

    //Creating an instance of Cli for parsing arguments
    let arguments = Cli::parse();

    //Creating a new instance of CapturePacket
    let capture_packets = CapturePacket::new();
    
    //Matching arguments with the provided arguments
    match arguments.arg1 {
        Some(arg) => {
            //If the first argument is list
            if arg=="list"{
                capture_packets.print_devices();
            }
            //if it is capture
            else if arg == "capture" {
                //if capture is called then check the third argument  
                if let Some(device_number) = arguments.arg2.as_deref() {

                    //pass the number to start capturing packets
                    let number:u8  = device_number.parse().unwrap();

                    //if the number passed is out of range or not matching
                    //Default or 0th device will be selected automatically
                    capture_packets.print_to_console(number);
                }
                else{
                    //If no serial is provided
                    println!("device selected is unavailable");
                }
            }
            //in case of invalid arguments
            else {
                println!("Invalid arguments try again");
            }       
        }
        None => {print!("No argument given");},
    }
}
