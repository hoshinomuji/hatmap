use anyhow::{anyhow, Context, Result};
use pnet::datalink::{self, Channel::Ethernet, DataLinkSender, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum as ipv4_checksum, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum as tcp_ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::net::{IpAddr, Ipv4Addr};

pub const IPV4_HEADER_LEN: usize = 20;
pub const TCP_HEADER_LEN: usize = 20;
pub const ETHERNET_HEADER_LEN: usize = 14;

#[derive(Debug, Clone)]
pub struct SynPacketSpec {
    pub source_ip: Ipv4Addr,
    pub destination_ip: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
}

pub fn build_syn_packet(spec: &SynPacketSpec) -> Result<[u8; IPV4_HEADER_LEN + TCP_HEADER_LEN]> {
    let mut packet = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN];
    {
        let mut ip =
            MutableIpv4Packet::new(&mut packet[..IPV4_HEADER_LEN]).context("create ipv4 packet")?;
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN) as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(spec.source_ip);
        ip.set_destination(spec.destination_ip);
        ip.set_checksum(ipv4_checksum(&ip.to_immutable()));
    }
    {
        let mut tcp =
            MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).context("create tcp packet")?;
        tcp.set_source(spec.source_port);
        tcp.set_destination(spec.destination_port);
        tcp.set_sequence(spec.sequence);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(64240);
        tcp.set_checksum(tcp_ipv4_checksum(
            &tcp.to_immutable(),
            &spec.source_ip,
            &spec.destination_ip,
        ));
    }
    Ok(packet)
}

#[allow(dead_code)]
pub fn build_ack_packet(
    spec: &SynPacketSpec,
    ack_number: u32,
) -> Result<[u8; IPV4_HEADER_LEN + TCP_HEADER_LEN]> {
    let mut packet = build_syn_packet(spec)?;
    let mut tcp =
        MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).context("create tcp ack packet")?;
    tcp.set_flags(TcpFlags::ACK);
    tcp.set_acknowledgement(ack_number);
    tcp.set_checksum(0);
    tcp.set_checksum(tcp_ipv4_checksum(
        &tcp.to_immutable(),
        &spec.source_ip,
        &spec.destination_ip,
    ));
    Ok(packet)
}

pub fn default_interface() -> Result<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| {
            iface.is_up()
                && !iface.is_loopback()
                && iface.mac.is_some()
                && iface.ips.iter().any(|ip| ip.is_ipv4())
        })
        .ok_or_else(|| anyhow!("no usable non-loopback interface found"))
}

pub fn interface_ipv4(interface: &NetworkInterface) -> Result<Ipv4Addr> {
    interface
        .ips
        .iter()
        .find_map(|network| match network.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| anyhow!("interface has no IPv4 address"))
}

pub fn open_sender(interface: &NetworkInterface) -> Result<Box<dyn DataLinkSender>> {
    match datalink::channel(interface, Default::default()).context("open datalink channel")? {
        Ethernet(tx, _) => Ok(tx),
        _ => Err(anyhow!("unsupported datalink channel type")),
    }
}

pub fn send_ipv4_tcp_frame(
    tx: &mut dyn DataLinkSender,
    interface: &NetworkInterface,
    destination_mac: MacAddr,
    payload: &[u8],
) -> Result<()> {
    let source_mac = interface
        .mac
        .ok_or_else(|| anyhow!("interface has no MAC address"))?;
    let mut frame = vec![0u8; ETHERNET_HEADER_LEN + payload.len()];
    let mut ethernet = MutableEthernetPacket::new(&mut frame).context("create ethernet packet")?;
    ethernet.set_source(source_mac);
    ethernet.set_destination(destination_mac);
    ethernet.set_ethertype(EtherTypes::Ipv4);
    ethernet.payload_mut().copy_from_slice(payload);

    tx.send_to(ethernet.packet(), None)
        .ok_or_else(|| anyhow!("datalink sender dropped packet"))?
        .context("send ethernet frame")
}
