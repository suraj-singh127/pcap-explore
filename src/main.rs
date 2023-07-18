use pcap::{Device, Capture, Active};
use clap::Parser;
pub mod parsepackets;
use parsepackets::ParsedPacket;
use parsepackets::PacketHeader;
use tls_parser::nom::AsBytes;

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
        arg4 : Option<String>,
    }
    
    //Declaring CapturePaceket
    pub struct CapturePacket {}

    //Implementing the CapturePacket struct
    impl CapturePacket {
        pub fn new() -> CapturePacket {
            CapturePacket {  }
        }
        
        pub fn print_error_function(&self, error:String){
            eprintln!("Error - {:?}",error);
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
                Err(err) => {
                    self.print_error_function(err.to_string());
                }
            }
            println!("\n=======================================================");
            println!("To capture packets from a device - cargo run capture [device_serial number]");
        }

        //Takes the serial number of the device in form of unsigned 8 bit unsigned integer 0-255
        pub fn start_capturing(&self , device_number:u8 , argument:String, filename:&str) {

            let deviceinfo = self.return_selected(device_number);
            
            //First a Capture<Inactive> handle is opened by passing the device or device name to Capture::from_device - pcap rust docs
            let cap2 = Capture::from_device(deviceinfo.0.as_str()).expect("error capturing");
            
            //Then the Capture<Inactive> is activated via .open() function and setting other configurations 
            let mut cap_handle = cap2.promisc(true).snaplen(100).timeout(10000).open().unwrap();

            //Once the device ready for Active Capturing we can list datalinks and use them accordingly
            let data_links = cap_handle.list_datalinks().expect("could not find");
            
            println!("\n===========================================================================================\n");
            println!("Links Available are - \n");
            for links in data_links{
                println!("{:?}",links.get_description().unwrap());
            }
            println!("\n===========================================================================================");
            println!("Capturing packets from - {}" ,deviceinfo.1);
            
            //For counting the number of packets
            let mut packet_no:i64 = 1;
            if argument == "capture"{
                //Now we can traverse over the captured packets by calling active capture handles .next() function            
                while let Ok(packet) = cap_handle.next() {
                    let data = packet.data.to_owned();
                    let len = packet.header.len;
    
                    //Formating the timestamps to be shown upto 6 digit of decimal 
                    let ts: String = format!("{}.{:06}",&packet.header.ts.tv_sec, &packet.header.ts.tv_usec);
    
                    //Creating a new instance of Parsed Packet
                    let packet_parse = ParsedPacket::new();
                    let parsed_packet = packet_parse.parse_packet(data, len, ts);
                    self.print_packet(parsed_packet,packet_no);
                    packet_no = packet_no + 1;
                    if packet_no > 1000 {
                        break;
                    }
                }
            }
            else {
                self.save_as_file(cap_handle, filename);
            }

        }

        //Saving packets to file
        pub fn save_as_file(&self,mut capture_handle:Capture<Active>,filename: &str){
            let mut packet_no = 1;

            //Capturing packets and saving them to file.
            match capture_handle.savefile(&filename) {

                //Writing each packet to file
                Ok(mut save_file) => {
                    while let Ok(packet) = capture_handle.next() {
                        save_file.write(&packet);
                        packet_no = packet_no + 1;
                        if packet_no > 1000 { 
                            println!("Done writing packets... ");   
                            break; 
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error - {:?}", e);
                }
            }
        }

        //Function for selecting the interface
        pub fn return_selected(&self, device_number:u8)
        -> (String,String)
        {
            //Creating a mutable string to store the device name
            let mut device_name = String::from("");
            let mut device_description = String::from("");

            //Looking for all the interfaces on the devices
            //Device::list() -> Returns a Result<T,E> type where -
            //T - Vector of Devices
            //E - Returns error if encountered
            let list = Device::list();
            
            let mut number = 1;

            //Matching the device number and returning the selected number 
            match list {
                Ok(devices) => {
                    device_name = devices[0].name.clone();
                    device_description = match &devices[0].desc {
                        Some(desc) => {
                            desc.to_string()
                        }
                        None => "Not Available".to_string()
                    };
                    //Iterating through the devices to select a device and clone its name
                    for device in devices {
                        if number == device_number{
                            device_name = device.name.clone();
                            device_description = device.desc.unwrap_or("Description not Available".to_string()).clone();
                        }
                        number  = number + 1;
                    }
                }
                Err(e) => {
                    eprint!("Error reading devices {:?}",e);
                }
            }

            //Returning the device name
            (device_name,device_description)

        }


        //Printing individual packets to console
        pub fn print_packet(&self,parsed_packet:Result<ParsedPacket,String>,packet_no:i64){
            println!("\n===========================================================================================\n");
            
            print!("\n==================================== Packet no. {} =======================================\n\n",packet_no);
            
            match parsed_packet {
                Ok(parsed_packet) => {
                    //parsed packet is passed to function for printing header info
                   self.header_information(parsed_packet);
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
                        println!("----------------- Information from Ethernet Frame ------------------");
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
                        println!("------------------ Information from IPV4 Header ------------------");
                        println!("Version - {}  IHL - {}",ipv4_header.version,ipv4_header.ihl);
                        println!("Length - {}   Protocol - {:?}", ipv4_header.length,ipv4_header.protocol);
                        println!("Source Address: {}  -----> Destination Address: {}",ipv4_header.source_addr,ipv4_header.dest_addr);
                    }

                    //for IPv6
                    PacketHeader::IPv6(ipv6_header)=> {
                        println!("----------------- Information from IPV6 Header -------------------");
                        println!("Version - {}  Hop Limit - {}", ipv6_header.version,ipv6_header.hop_limit);
                        println!("Length - {}   Protocol - {:?}", ipv6_header.length,ipv6_header.next_header);
                        println!("Source Address: {}  -----> Destination Address: {}",ipv6_header.source_addr,ipv6_header.dest_addr);
                    }

                    //For Arp header - if the packet uses ARP protocol
                    PacketHeader::Arp(arp_packet)=> {
                        
                        println!("----------------- Information from ARP Header --------------------");
                        println!("Hardware Addr Type:{}   Protocol Address Type:{:?}", arp_packet.hw_addr_size,arp_packet.proto_addr_type);
                        println!("Operation: {:?}",arp_packet.operation);
                        println!("Source MAC: {:?}  -----> Destination MAC: {:?}",arp_packet.src_mac,arp_packet.dest_mac);
                    }

                    //For printing TCP Header information
                    PacketHeader::Tcp(tcp_header) => {
                        println!("----------------- Information from TCP Header ------------------");
                        println!("Source Port: {} -----> Dest Port: {}",tcp_header.source_port,tcp_header.dest_port);
                        println!("Sequence No: {}   Ack No: {}",tcp_header.sequence_no,tcp_header.ack_no);
                        println!("FLAGS -   ACK: {}   FIN: {}   PSH: {}    RST: {}    SYN: {}   URG:{}",
                        &self.convert_flag(tcp_header.flag_ack),&self.convert_flag(tcp_header.flag_fin),
                        &self.convert_flag(tcp_header.flag_psh),&self.convert_flag(tcp_header.flag_rst),
                        &self.convert_flag(tcp_header.flag_syn),&self.convert_flag(tcp_header.flag_urg));
                        
                    }

                    //For printing UDP Header information
                    PacketHeader::UDP(udp_header) => {
                        println!("----------------- Information from UDP Header ------------------");
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

    //Creating an instance of Cli for parsing arguments
    let arguments = Cli::parse();

    // Creating a new instance of CapturePacket
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
                    capture_packets.start_capturing(number,"capture".to_string(),"");
                }
                else{
                    //If no serial is provided
                    println!("device selected is unavailable");
                }
            }
            else if arg == "save"{
                println!("Inside save block");

                if let Some(device_no) = arguments.arg2.as_deref(){

                    //Same thing done as above
                    let number:u8  = device_no.parse().unwrap();
                    if let Some(filename) = arguments.arg3.as_deref() {
                        println!("Saving to file path - {}",filename);
                        //Calling print to console with save argument
                        capture_packets.start_capturing(number, "save".to_string(), filename);
                    }
                    else{
                        println!("No filepath provided")
                    }

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
