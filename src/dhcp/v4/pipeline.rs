use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use dhcproto::{v4, Decodable, Encodable};

use crate::error::{RelayError, RelayResult};
use crate::pipeline::{Pipeline, PipelineContext, PipelineStage};

use super::giaddr::{self, GiaddrDecision};
use super::option82;

// ── ParseStage ────────────────────────────────────────────────────────────

/// Decodes a DHCPv4 message from the buffer and validates basic structure.
struct ParseStage;

impl PipelineStage for ParseStage {
    fn name(&self) -> &str {
        "dhcpv4::parse"
    }

    fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool> {
        let msg =
            v4::Message::decode(&mut dhcproto::Decoder::new(&ctx.buffer)).map_err(|e| {
                RelayError::Parse(format!("failed to parse DHCPv4 message: {e}"))
            })?;

        // Re-encode back to buffer for downstream stages
        let mut buf = Vec::new();
        msg.encode(&mut dhcproto::Encoder::new(&mut buf)).map_err(|e| {
            RelayError::Parse(format!("failed to encode DHCPv4 message: {e}"))
        })?;
        ctx.buffer = buf;

        Ok(true)
    }
}

// ── ValidateStage ─────────────────────────────────────────────────────────

/// Validates the giaddr field and enforces security invariants (RFC 3046).
struct ValidateStage {
    local_addrs: Vec<Ipv4Addr>,
}

impl PipelineStage for ValidateStage {
    fn name(&self) -> &str {
        "dhcpv4::validate"
    }

    fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool> {
        let msg =
            v4::Message::decode(&mut dhcproto::Decoder::new(&ctx.buffer)).map_err(|e| {
                RelayError::Parse(format!("validate decode: {e}"))
            })?;

        let decision = giaddr::validate(&msg, &self.local_addrs, ctx.is_trusted_circuit);

        match decision {
            GiaddrDecision::FirstRelay | GiaddrDecision::TrustedCircuit => {
                // OK, continue
                Ok(true)
            }
            GiaddrDecision::Reforwarded => {
                ctx.is_reforwarded = true;
                Ok(true)
            }
            GiaddrDecision::UntrustedCircuit => {
                tracing::warn!(
                    interface = %ctx.interface,
                    "untrusted circuit with Option 82 — dropping packet"
                );
                Ok(false)
            }
            GiaddrDecision::Spoof => {
                tracing::warn!(
                    giaddr = %msg.giaddr(),
                    "giaddr spoof detected — dropping packet"
                );
                Err(RelayError::GiaddrSpoof(format!(
                    "giaddr {} matches local interface",
                    msg.giaddr()
                )))
            }
        }
    }
}

// ── Option82InsertStage ───────────────────────────────────────────────────

/// Inserts Option 82 (Circuit ID + Remote ID) on client→server direction.
struct Option82InsertStage {
    circuit_id: Option<Vec<u8>>,
    remote_id: Option<Vec<u8>>,
}

impl PipelineStage for Option82InsertStage {
    fn name(&self) -> &str {
        "dhcpv4::option82::insert"
    }

    fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool> {
        if ctx.is_reforwarded {
            return Ok(true); // Don't modify reforwarded packets
        }

        let mut msg =
            v4::Message::decode(&mut dhcproto::Decoder::new(&ctx.buffer)).map_err(|e| {
                RelayError::Parse(format!("option82 insert decode: {e}"))
            })?;

        let circuit = self.circuit_id.as_deref();
        let remote = self.remote_id.as_deref();

        option82::insert(&mut msg, circuit, remote)?;

        let mut buf = Vec::new();
        msg.encode(&mut dhcproto::Encoder::new(&mut buf)).map_err(|e| {
            RelayError::Parse(format!("option82 insert encode: {e}"))
        })?;
        ctx.buffer = buf;

        ctx.metadata
            .insert("option82_inserted".into(), "true".into());

        Ok(true)
    }
}

// ── Option82StripStage ────────────────────────────────────────────────────

/// Strips Option 82 and validates echo on server→client direction.
struct Option82StripStage {
    expected_sub_opts: Option<Vec<option82::SubOption>>,
}

impl PipelineStage for Option82StripStage {
    fn name(&self) -> &str {
        "dhcpv4::option82::strip"
    }

    fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool> {
        let mut msg =
            v4::Message::decode(&mut dhcproto::Decoder::new(&ctx.buffer)).map_err(|e| {
                RelayError::Parse(format!("option82 strip decode: {e}"))
            })?;

        if let Some(expected) = &self.expected_sub_opts {
            // Verify echo: extract sub-options without removing, compare
            if let Some(relay_opt) = msg.opts().get(v4::OptionCode::RelayAgentInformation) {
                if let v4::DhcpOption::RelayAgentInformation(info) = relay_opt {
                    let received: Vec<option82::SubOption> =
                        info.iter().map(|(_, ri)| option82::relay_info_to_sub_opt(ri)).collect();
                    if !option82::validate_echo(&received, expected) {
                        return Err(RelayError::Option82Mismatch);
                    }
                }
            } else {
                return Err(RelayError::Option82Mismatch);
            }
        }

        option82::strip(&mut msg);

        let mut buf = Vec::new();
        msg.encode(&mut dhcproto::Encoder::new(&mut buf)).map_err(|e| {
            RelayError::Parse(format!("option82 strip encode: {e}"))
        })?;
        ctx.buffer = buf;

        Ok(true)
    }
}

// ── GiaddrStage ───────────────────────────────────────────────────────────

/// Sets the giaddr field to the relay interface IP on client→server direction.
struct GiaddrStage {
    iface_ip: Ipv4Addr,
}

impl PipelineStage for GiaddrStage {
    fn name(&self) -> &str {
        "dhcpv4::giaddr"
    }

    fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool> {
        if ctx.is_reforwarded {
            return Ok(true);
        }

        let mut msg =
            v4::Message::decode(&mut dhcproto::Decoder::new(&ctx.buffer)).map_err(|e| {
                RelayError::Parse(format!("giaddr decode: {e}"))
            })?;

        if msg.giaddr() == Ipv4Addr::UNSPECIFIED {
            msg.set_giaddr(self.iface_ip);
        }

        let mut buf = Vec::new();
        msg.encode(&mut dhcproto::Encoder::new(&mut buf)).map_err(|e| {
            RelayError::Parse(format!("giaddr encode: {e}"))
        })?;
        ctx.buffer = buf;

        Ok(true)
    }
}

// ── ForwardStage ──────────────────────────────────────────────────────────

/// Sets the destination address for the packet.
struct ForwardStage {
    dest: SocketAddr,
}

impl PipelineStage for ForwardStage {
    fn name(&self) -> &str {
        "dhcpv4::forward"
    }

    fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool> {
        ctx.dst_addr = Some(self.dest);
        Ok(true)
    }
}

// ── ReplyAddrStage ────────────────────────────────────────────────────────

/// Resolves the client address from the server reply (RFC 2131).
///
/// Priority: ciaddr → broadcast 255.255.255.255:68
struct ReplyAddrStage;

impl PipelineStage for ReplyAddrStage {
    fn name(&self) -> &str {
        "dhcpv4::reply_addr"
    }

    fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool> {
        let msg = v4::Message::decode(&mut dhcproto::Decoder::new(&ctx.buffer))
            .map_err(|e| RelayError::Parse(format!("reply_addr decode: {e}")))?;

        let client = if msg.ciaddr() != Ipv4Addr::UNSPECIFIED {
            SocketAddr::new(IpAddr::V4(msg.ciaddr()), 68)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)), 68)
        };

        ctx.dst_addr = Some(client);
        Ok(true)
    }
}

// ── Dhcpv4Pipeline ────────────────────────────────────────────────────────

/// Builder for DHCPv4 request and reply processing pipelines.
pub struct Dhcpv4Pipeline;

impl Dhcpv4Pipeline {
    /// Build the client→server (request relay) pipeline.
    ///
    /// Stages: Parse → Validate → Option82(insert) → Giaddr(set) → Forward
    pub fn build_request(
        local_addrs: Vec<Ipv4Addr>,
        circuit_id: Option<Vec<u8>>,
        remote_id: Option<Vec<u8>>,
        iface_ip: Ipv4Addr,
        server_addr: SocketAddr,
    ) -> Pipeline {
        let stages: Vec<Box<dyn PipelineStage>> = vec![
            Box::new(ParseStage),
            Box::new(ValidateStage { local_addrs }),
            Box::new(Option82InsertStage {
                circuit_id,
                remote_id,
            }),
            Box::new(GiaddrStage { iface_ip }),
            Box::new(ForwardStage { dest: server_addr }),
        ];
        Pipeline::with_stages(stages)
    }

    /// Build the server→client (reply relay) pipeline.
    ///
    /// Stages: Parse → Option82(strip+echo check) → ReplyAddr(resolve) → Forward
    pub fn build_reply(
        expected_sub_opts: Option<Vec<option82::SubOption>>,
    ) -> Pipeline {
        let stages: Vec<Box<dyn PipelineStage>> = vec![
            Box::new(ParseStage),
            Box::new(Option82StripStage { expected_sub_opts }),
            Box::new(ReplyAddrStage),
        ];
        Pipeline::with_stages(stages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn client_context() -> PipelineContext {
        PipelineContext::new(
            vec![],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 68),
            "eth0".into(),
        )
    }

    fn make_discover_bytes() -> Vec<u8> {
        let mut msg = v4::Message::default();
        msg.opts_mut()
            .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover));
        let mut buf = Vec::new();
        msg.encode(&mut dhcproto::Encoder::new(&mut buf)).unwrap();
        buf
    }

    #[test]
    fn request_pipeline_first_relay_inserts_option82_and_sets_giaddr() {
        let local_addrs = vec![Ipv4Addr::new(10, 0, 0, 1)];
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)), 67);

        let mut pipeline = Dhcpv4Pipeline::build_request(
            local_addrs,
            Some(b"eth0".to_vec()),
            Some(b"relay1".to_vec()),
            Ipv4Addr::new(10, 0, 0, 1),
            server,
        );

        let mut ctx = client_context();
        ctx.buffer = make_discover_bytes();

        let result = pipeline.execute(&mut ctx).unwrap();
        assert!(result, "pipeline should forward the packet");

        // Verify giaddr was set
        let msg =
            v4::Message::decode(&mut dhcproto::Decoder::new(&ctx.buffer)).unwrap();
        assert_eq!(msg.giaddr(), Ipv4Addr::new(10, 0, 0, 1));

        // Verify Option 82 was inserted
        assert!(msg.opts().contains(v4::OptionCode::RelayAgentInformation));

        // Verify destination is the server
        assert_eq!(ctx.dst_addr, Some(server));
    }

    #[test]
    fn request_pipeline_drops_spoofed_packet() {
        let local_addrs = vec![Ipv4Addr::new(10, 0, 0, 1)];

        let mut pipeline = Dhcpv4Pipeline::build_request(
            local_addrs,
            Some(b"eth0".to_vec()),
            None,
            Ipv4Addr::new(10, 0, 0, 1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)), 67),
        );

        let mut ctx = client_context();
        // Create a message with giaddr set to the local address (spoof)
        let mut msg = v4::Message::default();
        msg.set_giaddr(Ipv4Addr::new(10, 0, 0, 1)); // matches local
        let mut buf = Vec::new();
        msg.encode(&mut dhcproto::Encoder::new(&mut buf)).unwrap();
        ctx.buffer = buf;

        let result = pipeline.execute(&mut ctx);
        assert!(result.is_err()); // Spoof → error
    }

    #[test]
    fn reply_pipeline_strips_option82() {
        // Build a server OFFER with echoed Option 82
        let mut msg = v4::Message::default();
        msg.set_opcode(dhcproto::v4::Opcode::BootReply);
        msg.opts_mut()
            .insert(v4::DhcpOption::MessageType(v4::MessageType::Offer));

        // Insert a dummy Option 82 (simulating echo)
        let mut agent_info = v4::relay::RelayAgentInformation::default();
        agent_info.insert(v4::relay::RelayInfo::AgentCircuitId(b"eth0".to_vec()));
        msg.opts_mut()
            .insert(v4::DhcpOption::RelayAgentInformation(agent_info));

        let mut buf = Vec::new();
        msg.encode(&mut dhcproto::Encoder::new(&mut buf)).unwrap();

        let expected = vec![option82::SubOption::new(1, b"eth0".to_vec())];

        let mut pipeline = Dhcpv4Pipeline::build_reply(Some(expected));

        let mut ctx = client_context();
        ctx.buffer = buf;

        let result = pipeline.execute(&mut ctx).unwrap();
        assert!(result, "pipeline should forward the packet");

        // Verify Option 82 was stripped
        let msg =
            v4::Message::decode(&mut dhcproto::Decoder::new(&ctx.buffer)).unwrap();
        assert!(!msg.opts().contains(v4::OptionCode::RelayAgentInformation));

        // Verify destination is broadcast (ciaddr was 0)
        assert_eq!(
            ctx.dst_addr,
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)), 68))
        );
    }

    #[test]
    fn reply_pipeline_echo_mismatch_is_error() {
        let mut msg = v4::Message::default();
        msg.set_opcode(dhcproto::v4::Opcode::BootReply);
        msg.opts_mut()
            .insert(v4::DhcpOption::MessageType(v4::MessageType::Offer));
        let mut agent_info = v4::relay::RelayAgentInformation::default();
        agent_info.insert(v4::relay::RelayInfo::AgentCircuitId(b"wrong-id".to_vec()));
        msg.opts_mut()
            .insert(v4::DhcpOption::RelayAgentInformation(agent_info));

        let mut buf = Vec::new();
        msg.encode(&mut dhcproto::Encoder::new(&mut buf)).unwrap();

        // Expected is different from what server echoed
        let expected = vec![option82::SubOption::new(1, b"eth0".to_vec())];

        let mut pipeline = Dhcpv4Pipeline::build_reply(Some(expected));

        let mut ctx = client_context();
        ctx.buffer = buf;

        let result = pipeline.execute(&mut ctx);
        assert!(result.is_err()); // Option 82 echo mismatch
    }

    #[test]
    fn request_pipeline_reforwarded_does_not_modify() {
        let local_addrs = vec![Ipv4Addr::new(10, 0, 0, 1)];

        let mut pipeline = Dhcpv4Pipeline::build_request(
            local_addrs,
            Some(b"eth0".to_vec()),
            Some(b"relay1".to_vec()),
            Ipv4Addr::new(10, 0, 0, 1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)), 67),
        );

        let mut ctx = client_context();
        // Create a reforwarded message: giaddr != 0, not local
        let mut msg = v4::Message::default();
        msg.set_giaddr(Ipv4Addr::new(172, 16, 0, 1)); // remote relay
        let mut buf = Vec::new();
        msg.encode(&mut dhcproto::Encoder::new(&mut buf)).unwrap();
        ctx.buffer = buf;

        let result = pipeline.execute(&mut ctx).unwrap();
        assert!(result, "reforwarded packet should be forwarded");

        // Verify giaddr was NOT changed
        let msg =
            v4::Message::decode(&mut dhcproto::Decoder::new(&ctx.buffer)).unwrap();
        assert_eq!(msg.giaddr(), Ipv4Addr::new(172, 16, 0, 1));

        // Verify Option 82 was NOT inserted
        assert!(!msg.opts().contains(v4::OptionCode::RelayAgentInformation));
    }
}
