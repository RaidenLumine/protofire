//! src/user/program/shell/commands/network.rs
//!
//! Network commands (ping).

use super::super::entry::current_process;
use crate::kernel::network;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

// ─── ping ────────────────────────────────────────────────────────────

/// Build a simple payload for an ICMP Echo Request (56 bytes of padding).
fn build_ping_payload(seq: u8) -> Vec<u8> {
    let mut payload = alloc::vec![0u8; 56];
    for byte in payload.iter_mut() {
        *byte = seq;
    }
    // Stamp a small timestamp pattern at the start.
    if payload.len() >= 8 {
        payload[0] = b'A';
        payload[1] = b'd';
        payload[2] = b'A';
        payload[3] = b's';
        payload[4] = b't';
        payload[5] = b'r';
        payload[6] = b'a';
        payload[7] = seq;
    }
    payload
}

pub(crate) fn cmd_ping(_cwd: &str, argv: &[String]) -> String {
    let mut count: u32 = 4;
    let mut deadline_secs: u64 = 10;
    let mut host: Option<&str> = None;

    let args: Vec<&str> = argv.iter().skip(1).map(|s| s.as_str()).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-c" => {
                if i + 1 < args.len() {
                    count = args[i + 1].parse::<u32>().unwrap_or(4);
                    i += 2;
                } else {
                    return String::from("ping: missing count after -c\n");
                }
            }
            "-w" => {
                if i + 1 < args.len() {
                    deadline_secs = args[i + 1].parse::<u64>().unwrap_or(10);
                    i += 2;
                } else {
                    return String::from("ping: missing deadline after -w\n");
                }
            }
            other => {
                host = Some(other);
                i += 1;
            }
        }
    }

    let Some(host) = host else {
        return String::from("ping: usage: ping [-c <count>] [-w <seconds>] <host>\n");
    };

    if !network::status().available() {
        return String::from("ping: network unavailable\n");
    }

    // Resolve hostname to IP.
    let dst_ip = match network::dns::resolve_hostname(host) {
        Ok(ip) => ip,
        Err(_) => return format!("ping: cannot resolve `{host}`\n"),
    };

    let Some(stack) = network::stack::NetworkStack::global() else {
        return String::from("ping: network stack not initialised\n");
    };

    let src_ip = stack.local_ip();
    let id = current_process()
        .map(|p| (p.pid() & 0xFFFF) as u16)
        .unwrap_or(0);

    let mut out = format!(
        "PING {host} ({}.{}.{}.{}) 56 data bytes\n",
        dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]
    );

    let mut sent = 0u32;
    let mut received = 0u32;
    let mut rtts: Vec<u64> = Vec::new();

    for seq in 1..=count {
        let rest_of_header = ((id as u32) << 16) | seq;
        let echo_header = network::internet::icmp::IcmpHeader {
            icmp_type: network::internet::icmp::ICMP_TYPE_ECHO_REQUEST,
            code: 0,
            checksum: 0,
            rest_of_header,
        };
        let payload = build_ping_payload(seq as u8);
        let icmp_msg = network::internet::icmp::build_icmp_message(&echo_header, &payload);

        let ip_header = network::internet::ipv4::Ipv4Header {
            total_length: 0,
            identification: 0,
            flags_fragment_offset: 0,
            ttl: network::internet::ipv4::IPV4_DEFAULT_TTL,
            protocol: network::internet::ipv4::IpProtocol::Icmp,
            header_checksum: 0,
            source: src_ip,
            destination: dst_ip,
        };
        let raw_ip = network::internet::ipv4::build_packet(&ip_header, &icmp_msg);

        // Register pending ping.
        let sent_tick = stack.current_tick();
        network::internet::icmp::PENDING_PINGS
            .lock()
            .push(network::internet::icmp::PendingPing {
                id,
                seq: seq as u16,
                dst: dst_ip,
                sent_at: sent_tick,
                reply_at: core::cell::Cell::new(0),
            });

        // Send.
        if let Err(e) = stack.send_ipv4_packet(dst_ip, raw_ip) {
            out.push_str(&format!("ping: send error — {}\n", e.as_str()));
            break;
        }
        sent += 1;

        // Poll loop waiting for reply.
        let deadline_tick = sent_tick + deadline_secs * 100; // 100 Hz ticks
        loop {
            let _ = stack.poll();

            if stack.current_tick() >= deadline_tick {
                out.push_str(&format!("Request timeout for icmp_seq={seq}\n"));
                break;
            }

            let pings = network::internet::icmp::PENDING_PINGS.lock();
            let found = pings
                .iter()
                .find(|p| p.id == id && p.seq == seq as u16 && p.reply_at.get() != 0);
            if let Some(ping) = found {
                let rtt_ticks = ping.reply_at.get() - ping.sent_at;
                let rtt_ms = rtt_ticks.saturating_mul(10); // 1 tick = 10 ms at 100 Hz
                received += 1;
                rtts.push(rtt_ms);

                out.push_str(&format!(
                    "64 bytes from {}.{}.{}.{}: icmp_seq={} ttl={} time={} ms\n",
                    dst_ip[0],
                    dst_ip[1],
                    dst_ip[2],
                    dst_ip[3],
                    seq,
                    network::internet::ipv4::IPV4_DEFAULT_TTL,
                    rtt_ms,
                ));
                break;
            }
        }
    }

    // Summary.
    if sent > 0 {
        let loss = ((sent.wrapping_sub(received)) * 100)
            .checked_div(sent)
            .unwrap_or(0);
        out.push_str(&format!(
            "--- {host} ping statistics ---\n\
             {sent} packets transmitted, {received} received, {loss}% packet loss\n",
        ));
        if !rtts.is_empty() {
            let min = rtts.iter().min().copied().unwrap_or(0);
            let max = rtts.iter().max().copied().unwrap_or(0);
            let sum: u64 = rtts.iter().sum();
            let avg = sum / rtts.len() as u64;
            out.push_str(&format!("rtt min/avg/max = {min}/{avg}/{max} ms\n",));
        }
    }

    // Clean up pending pings for this run.
    network::internet::icmp::PENDING_PINGS
        .lock()
        .retain(|p| p.id != id);

    out
}
