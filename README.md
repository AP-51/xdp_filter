# A Basic Packet Filter
This is a basic packet filter that I wrote while exploring XDP, eBPF and their capabilities. 

## Prerequisites
- `clang`
- `llvm`

### Compiling the BPF C program
```shell
$ clang -O2 -target bpf -c packet_parser.c -o packet_parser.o
```

### Loading the XDP program (using `ip`)
```shell
$ sudo ip link set dev lo xdpgeneric obj packet_parser.o
```
### Unloading the XDP program
```shell
$ sudo ip link set dev lo xdpgeneric off
```
### Usage/Testing
Once the XDP program is attached to an interface, it can be tested by sending packets to that interface. 
- For ICMP (ping) requests, I set up a bridge between my host machine and a VM and sent ping requests from the VM to the host after assigning appropriate IPs.
- For TCP/UDP requests, I opened two terminals and set up `netcat` tunnels in each of them. One for listening and one for sending data.

### Setting up Netcat
- Install `nmap` and use `ncat` from nmap as it supports IPV6 unlike `gnu-netcat`
- For listening packets, use:
```shell
$ ncat -l -p port_number host_ip
```
- For sending packets, use:
```shell
$ ncat host_ip port_number
```
- Additional options: Use `ncat -6` for IPV6 and `ncat -u` for UDP. Default is TCP

### Configuring the IPs
The source IP addresses to be filtered can be changed in `packet_parser.c` and then can be recompiled for use.
