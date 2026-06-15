use std::net::SocketAddr;

use dhcproto::{v6, Decodable, Encodable};

use crate::config::VssConfig;
use crate::error::{RelayError, RelayResult};
use crate::pipeline::{Pipeline, PipelineContext, PipelineStage};

use super::interface_id;
use super::relay_fwd::RelayFwdCodec;
use super::remote_id;
use super::vss;

// ── ParseStage ────────────────────────────────────────────────────────────

struct ParseStage;

impl PipelineStage for ParseStage {
    fn name(&self) -> &str {
        "dhcpv6::parse"
    }

    fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool> {
        v6::Message::decode(&mut dhcproto::Decoder::new(&ctx.buffer)).map_err(|e| {
            RelayError::Parse(format!("failed to parse DHCPv6 message: {e}"))
        })?;
        Ok(true)
    }
}

// ── InterfaceIdStage ──────────────────────────────────────────────────────

struct InterfaceIdStage {
    iface_name: String,
}

impl PipelineStage for InterfaceIdStage {
    fn name(&self) -> &str {
        "dhcpv6::interface_id"
    }

    fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool> {
        let mut msg =
            v6::Message::decode(&mut dhcproto::Decoder::new(&ctx.buffer)).map_err(|e| {
                RelayError::Parse(format!("interface-id decode: {e}"))
            })?;

        let opt = interface_id::encode(&self.iface_name);
        msg.opts_mut().insert(opt);

        let mut buf = Vec::new();
        msg.encode(&mut dhcproto::Encoder::new(&mut buf)).map_err(|e| {
            RelayError::Parse(format!("interface-id encode: {e}"))
        })?;
        ctx.buffer = buf;

        Ok(true)
    }
}

// ── RemoteIdStage ─────────────────────────────────────────────────────────

struct RemoteIdStage {
    remote_id: Vec<u8>,
}

impl PipelineStage for RemoteIdStage {
    fn name(&self) -> &str {
        "dhcpv6::remote_id"
    }

    fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool> {
        let mut msg =
            v6::Message::decode(&mut dhcproto::Decoder::new(&ctx.buffer)).map_err(|e| {
                RelayError::Parse(format!("remote-id decode: {e}"))
            })?;

        let opt = remote_id::encode(&self.remote_id);
        msg.opts_mut().insert(opt);

        let mut buf = Vec::new();
        msg.encode(&mut dhcproto::Encoder::new(&mut buf)).map_err(|e| {
            RelayError::Parse(format!("remote-id encode: {e}"))
        })?;
        ctx.buffer = buf;

        Ok(true)
    }
}

// ── RelayFwdStage ─────────────────────────────────────────────────────────

struct RelayFwdStage {
    link_addr: std::net::Ipv6Addr,
    peer_addr: SocketAddr,
}

impl PipelineStage for RelayFwdStage {
    fn name(&self) -> &str {
        "dhcpv6::relay_fwd"
    }

    fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool> {
        // The buffer contains the client message with options added.
        // Wrap it in a Relay-forward message.
        let relay_fwd = RelayFwdCodec::encapsulate(
            &ctx.buffer,
            self.link_addr,
            self.peer_addr,
        );
        ctx.buffer = relay_fwd;

        Ok(true)
    }
}

// ── RelayReplyStage ───────────────────────────────────────────────────────

struct RelayReplyStage;

impl PipelineStage for RelayReplyStage {
    fn name(&self) -> &str {
        "dhcpv6::relay_reply"
    }

    fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool> {
        let inner = RelayFwdCodec::decapsulate(&ctx.buffer)?;
        ctx.buffer = inner;

        Ok(true)
    }
}

// ── InterfaceIdExtractStage ───────────────────────────────────────────────

struct InterfaceIdExtractStage;

impl PipelineStage for InterfaceIdExtractStage {
    fn name(&self) -> &str {
        "dhcpv6::interface_id_extract"
    }

    fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool> {
        let msg =
            v6::Message::decode(&mut dhcproto::Decoder::new(&ctx.buffer)).map_err(|e| {
                RelayError::Parse(format!("interface-id extract decode: {e}"))
            })?;

        // Extract interface-id to determine which interface to send to
        for opt in msg.opts().iter() {
            if let Some(name) = interface_id::decode(opt) {
                ctx.metadata.insert("outbound_interface".into(), name);
                break;
            }
        }

        Ok(true)
    }
}

// ── ForwardStage ──────────────────────────────────────────────────────────

struct ForwardStage {
    dest: SocketAddr,
}

impl PipelineStage for ForwardStage {
    fn name(&self) -> &str {
        "dhcpv6::forward"
    }

    fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool> {
        ctx.dst_addr = Some(self.dest);
        Ok(true)
    }
}

// ── VssInsertStage ────────────────────────────────────────────────────────

struct VssInsertStage {
    vss_config: VssConfig,
}

impl PipelineStage for VssInsertStage {
    fn name(&self) -> &str {
        "dhcpv6::vss::insert"
    }

    fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool> {
        if !self.vss_config.enabled {
            return Ok(true);
        }

        let vss_opt = vss::encode(&self.vss_config)?;

        let mut msg = v6::Message::decode(&mut dhcproto::Decoder::new(&ctx.buffer))
            .map_err(|e| RelayError::Parse(format!("v6 vss decode: {e}")))?;

        msg.opts_mut().insert(vss_opt);

        ctx.metadata
            .insert("vss_inserted".into(), "true".into());

        let mut buf = Vec::new();
        msg.encode(&mut dhcproto::Encoder::new(&mut buf))
            .map_err(|e| RelayError::Parse(format!("v6 vss encode: {e}")))?;
        ctx.buffer = buf;

        Ok(true)
    }
}

// ── VssExtractStage ───────────────────────────────────────────────────────

struct VssExtractStage {
    vss_config: VssConfig,
}

impl PipelineStage for VssExtractStage {
    fn name(&self) -> &str {
        "dhcpv6::vss::extract"
    }

    fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool> {
        if !self.vss_config.enabled {
            return Ok(true);
        }

        let msg = v6::Message::decode(&mut dhcproto::Decoder::new(&ctx.buffer))
            .map_err(|e| RelayError::Parse(format!("v6 vss extract decode: {e}")))?;

        let opts: Vec<_> = msg.opts().iter().cloned().collect();
        if let Some((vss_type, vss_info)) = vss::extract(&opts) {
            if let Some(ref expected_vpn) = self.vss_config.vpn_name {
                if vss_type == 0 {
                    // NVT ASCII
                    let vpn_name = std::str::from_utf8(&vss_info).unwrap_or("");
                    if vpn_name != expected_vpn.as_str() {
                        tracing::warn!(
                            vpn_name = vpn_name,
                            expected = expected_vpn.as_str(),
                            "VPN name mismatch"
                        );
                    }
                }
            }
        }

        Ok(true)
    }
}

// ── Dhcpv6Pipeline ────────────────────────────────────────────────────────

pub struct Dhcpv6Pipeline;

impl Dhcpv6Pipeline {
    /// Build the client→server (request relay) pipeline.
    ///
    /// Stages: Parse → InterfaceId → RemoteId → VSS(insert) → RelayFwd → Forward
    pub fn build_request(
        iface_name: String,
        remote_id: Vec<u8>,
        link_addr: std::net::Ipv6Addr,
        peer_addr: SocketAddr,
        server_addr: SocketAddr,
        vss_config: Option<VssConfig>,
    ) -> Pipeline {
        let mut stages: Vec<Box<dyn PipelineStage>> = vec![
            Box::new(ParseStage),
            Box::new(InterfaceIdStage { iface_name }),
            Box::new(RemoteIdStage { remote_id }),
        ];

        if let Some(cfg) = vss_config {
            stages.push(Box::new(VssInsertStage { vss_config: cfg }));
        }

        stages.push(Box::new(RelayFwdStage {
            link_addr,
            peer_addr,
        }));
        stages.push(Box::new(ForwardStage { dest: server_addr }));
        Pipeline::with_stages(stages)
    }

    /// Build the server→client (reply relay) pipeline.
    ///
    /// Stages: Parse → VSS(extract) → RelayReply(decapsulate) → InterfaceIdExtract → Forward
    pub fn build_reply(
        client_addr: SocketAddr,
        vss_config: Option<VssConfig>,
    ) -> Pipeline {
        let mut stages: Vec<Box<dyn PipelineStage>> = vec![Box::new(ParseStage)];

        if let Some(cfg) = vss_config {
            stages.push(Box::new(VssExtractStage { vss_config: cfg }));
        }

        stages.push(Box::new(RelayReplyStage));
        stages.push(Box::new(InterfaceIdExtractStage));
        stages.push(Box::new(ForwardStage { dest: client_addr }));
        Pipeline::with_stages(stages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};

    fn client_solicit_bytes() -> Vec<u8> {
        let msg = v6::Message::new(v6::MessageType::Solicit);
        let mut buf = Vec::new();
        msg.encode(&mut dhcproto::Encoder::new(&mut buf)).unwrap();
        buf
    }

    #[test]
    fn request_pipeline_encapsulates_in_relay_forward() {
        let server = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(2001, 0xdb8, 0, 0, 0, 0, 0, 100)),
            547,
        );
        let peer = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 546);
        let link = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

        let mut pipeline = Dhcpv6Pipeline::build_request(
            "eth0".into(),
            b"agent-1".to_vec(),
            link,
            peer,
            server,
            None,
        );

        let mut ctx = PipelineContext::new(
            vec![],
            peer,
            "eth0".into(),
        );
        ctx.buffer = client_solicit_bytes();

        let result = pipeline.execute(&mut ctx).unwrap();
        assert!(result);

        // Verify the output is a RELAY_FORW message
        assert_eq!(ctx.buffer[0], 12); // RELAY_FORW msg_type
        assert_eq!(ctx.dst_addr, Some(server));
    }

    #[test]
    fn reply_pipeline_decapsulates_relay_reply() {
        let advertise = {
            let msg = v6::Message::new(v6::MessageType::Advertise);
            let mut buf = Vec::new();
            msg.encode(&mut dhcproto::Encoder::new(&mut buf)).unwrap();
            buf
        };

        let relay_reply = RelayFwdCodec::encapsulate(
            &advertise,
            Ipv6Addr::LOCALHOST,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 546),
        );
        // Override msg_type to RELAY_REPL for a proper reply
        let mut reply = relay_reply;
        reply[0] = 13; // RELAY_REPL

        let client = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 546);
        let mut pipeline = Dhcpv6Pipeline::build_reply(client, None);

        let mut ctx = PipelineContext::new(
            vec![],
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(2001, 0xdb8, 0, 0, 0, 0, 0, 100)), 547),
            "eth0".into(),
        );
        ctx.buffer = reply;

        let result = pipeline.execute(&mut ctx).unwrap();
        assert!(result);
        assert_eq!(ctx.dst_addr, Some(client));

        // Verify the inner message is the ADVERTISE
        let inner =
            v6::Message::decode(&mut dhcproto::Decoder::new(&ctx.buffer)).unwrap();
        assert_eq!(inner.msg_type(), v6::MessageType::Advertise);
    }
}
