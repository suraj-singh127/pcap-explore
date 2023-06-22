use pcap::{Device};
extern crate rawsock;
use rawsock::open_best_library;

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
    // let capture_packets = CapturePacket::new();
    // capture_packets.print_devices();
    // capture_packets.print_to_console();

    println!("Opening packet capturing library");
    let lib = open_best_library().expect("Could not open any packet capturing library");
    println!("Library opened, version is {}", lib.version());
    let interf_name = "Wi-fi"; //replace with whatever is available on your platform
    println!("Opening the {} interface", interf_name);
    let mut interf = lib.open_interface(&interf_name).expect("Could not open network interface");
    println!("Interface opened, data link: {}", interf.data_link());

    println!("Receiving 5 packets:");
    for _ in 0..5 {
        let packet = interf.receive().expect("Could not receive packet");
        println!("Received packet: {}", packet);
    }

}
