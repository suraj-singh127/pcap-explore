use std::fmt::Debug;
use pcap::{Device, Capture};


fn main() {
    pub struct CapturePacket {
        err_count: u64,
    }

    impl CapturePacket {
        pub fn new() -> CapturePacket {
            CapturePacket { err_count: 0 }
        }

        pub fn print_devices(&self) {
            let list = Device::list();

            println!("\n====================================================");
            //The list of devices found
            print!("List of Devices found - \n\n");
            match list {
                Ok(devices) => {
                    for device in devices {
                        print!("Name - {}",device.name);
                        match device.desc {
                            Some(desc) => print!("{}", desc),
                            None => print!("Description not available"),
                        }
                        println!()
                    }
                }
                Err(error) => println!("Error: {}", error),
            }
        }

        pub fn headers(&self) {
            println!(
                "{0: <25} | {1: <15} | {2: <25} | {3: <15} | {4: <15} | {5: <15} | {6: <35} |",
                "Source IP",
                "Source Port",
                "Dest IP",
                "Dest Port",
                "Protocol",
                "Length",
                "Timestamp"
            );
            println!("{:-^1$}", "-", 165,);
        }

        pub fn print_to_console(&self) {
            let device_name = r"\Device\NPF_{4B9201ED-543E-41F2-9602-03F282DDE5D5}";
            let cap2 = Capture::from_device(device_name).expect("error capturing");
            let mut cap_handle = cap2.promisc(true).snaplen(5000).timeout(10000).open().unwrap();
            let data_links = cap_handle.list_datalinks().expect("could not find");
            for links in data_links{
                println!("{:?}",links);
            }
            while let Ok(packet) = cap_handle.next() {
                let data = packet.data;
                println!("{:?}",packet.header);
            }
        }
        
    }
    let capture_packets = CapturePacket::new();
    capture_packets.print_devices();
    capture_packets.print_to_console();

}
