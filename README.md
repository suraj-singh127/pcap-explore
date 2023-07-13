# Packet Sniffer Using Rust

A packet sniffer that intercepts the network traffic and analyzes the raw data packets. Further these packets will be analyzed using a packet sniffing software that presents these raw data packets to the user in a user friendly format. 

## Usage

To use this packet sniffer use the following commands on you pc -

1. Clone this repository -
```sh 
git clone https://github.com/suraj-singh127/pcap-explore
```

2. Now once inside the repository write the following command to build the crate -
```sh
cargo build
```

3. To list all the available interfaces - 
```sh
cargo run list 
```

4. To capture packets from the above mentioned list of interfaces(device no should be no listed above) - 
```sh
cargo run capture device_number 
```

5. To save packets to a file - 
```sh
cargo run save device_no file_name_here
```
