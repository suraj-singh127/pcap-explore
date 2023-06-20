use pcap::{Active, Capture, Device};
use libpcap;

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
            let devices_list = Device::list();
            match devices_list {
                Ok(devices) => {
                    print!("Capturing Packets from - {:?}", devices[4]);
                    
                }
                Err(err) => {eprintln!("{}",err)}
            }
        }
    }

}
