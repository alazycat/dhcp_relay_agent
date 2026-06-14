use std::collections::HashMap;
use std::net::SocketAddr;

use crate::error::RelayResult;

/// Context passed through each stage of the DHCP processing pipeline.
pub struct PipelineContext {
    /// Original inbound packet bytes (unmodified reference for echo verification).
    pub raw_in: Vec<u8>,
    /// Working buffer — stages read from and write to this.
    pub buffer: Vec<u8>,
    /// Source address of the received packet.
    pub src_addr: SocketAddr,
    /// Name of the interface that received the packet.
    pub interface: String,
    /// Destination address for forwarding the packet.
    pub dst_addr: Option<SocketAddr>,
    /// Whether this packet has been reforwarded (giaddr != 0 for v4, or hop-count > 0 for v6).
    pub is_reforwarded: bool,
    /// Whether the downstream circuit is trusted (for DHCPv4 trusted port handling).
    pub is_trusted_circuit: bool,
    /// Arbitrary metadata bag for inter-stage communication.
    pub metadata: HashMap<String, String>,
}

impl PipelineContext {
    pub fn new(raw_in: Vec<u8>, src_addr: SocketAddr, interface: String) -> Self {
        let buffer = raw_in.clone();
        Self {
            raw_in,
            buffer,
            src_addr,
            interface,
            dst_addr: None,
            is_reforwarded: false,
            is_trusted_circuit: false,
            metadata: HashMap::new(),
        }
    }
}

/// A single stage in a DHCP processing pipeline.
///
/// Each stage inspects or transforms the `PipelineContext`. Return `Ok(false)` to
/// halt the pipeline (drop the packet) without error. Return `Ok(true)` to continue
/// to the next stage.
pub trait PipelineStage: Send + Sync {
    fn name(&self) -> &str;
    fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool>;
}

/// An ordered chain of pipeline stages.
pub struct Pipeline {
    stages: Vec<Box<dyn PipelineStage>>,
}

impl Pipeline {
    pub fn new() -> Self {
        Self { stages: Vec::new() }
    }

    pub fn with_stages(stages: Vec<Box<dyn PipelineStage>>) -> Self {
        Self { stages }
    }

    pub fn add_stage(&mut self, stage: Box<dyn PipelineStage>) {
        self.stages.push(stage);
    }

    /// Execute all stages in order. Returns `Ok(true)` if the packet should be
    /// forwarded, `Ok(false)` if it was dropped by a stage, or an error.
    pub fn execute(&mut self, ctx: &mut PipelineContext) -> RelayResult<bool> {
        for stage in &self.stages {
            let result = stage.process(ctx)?;
            if !result {
                tracing::debug!(
                    stage = stage.name(),
                    "pipeline halted — packet dropped"
                );
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }

    pub fn len(&self) -> usize {
        self.stages.len()
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    struct DummyStage {
        name: &'static str,
        should_continue: bool,
    }

    impl PipelineStage for DummyStage {
        fn name(&self) -> &str {
            self.name
        }

        fn process(&self, _ctx: &mut PipelineContext) -> RelayResult<bool> {
            Ok(self.should_continue)
        }
    }

    struct MetadataStage;

    impl PipelineStage for MetadataStage {
        fn name(&self) -> &str {
            "metadata"
        }

        fn process(&self, ctx: &mut PipelineContext) -> RelayResult<bool> {
            ctx.metadata
                .insert("processed".to_string(), "true".to_string());
            Ok(true)
        }
    }

    fn test_ctx() -> PipelineContext {
        PipelineContext::new(
            vec![1, 2, 3],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 68),
            "eth0".to_string(),
        )
    }

    #[test]
    fn pipeline_executes_all_stages() {
        let mut pipeline = Pipeline::with_stages(vec![
            Box::new(DummyStage {
                name: "s1",
                should_continue: true,
            }),
            Box::new(DummyStage {
                name: "s2",
                should_continue: true,
            }),
        ]);
        let mut ctx = test_ctx();
        assert!(pipeline.execute(&mut ctx).unwrap());
    }

    #[test]
    fn pipeline_halts_on_false() {
        let mut pipeline = Pipeline::with_stages(vec![
            Box::new(DummyStage {
                name: "s1",
                should_continue: false,
            }),
            Box::new(DummyStage {
                name: "s2",
                should_continue: true,
            }),
        ]);
        let mut ctx = test_ctx();
        assert!(!pipeline.execute(&mut ctx).unwrap());
    }

    #[test]
    fn pipeline_stages_can_set_metadata() {
        let mut pipeline = Pipeline::with_stages(vec![Box::new(MetadataStage)]);
        let mut ctx = test_ctx();
        pipeline.execute(&mut ctx).unwrap();
        assert_eq!(ctx.metadata.get("processed").unwrap(), "true");
    }

    #[test]
    fn pipeline_context_defaults() {
        let ctx = test_ctx();
        assert!(!ctx.is_reforwarded);
        assert!(!ctx.is_trusted_circuit);
        assert!(ctx.dst_addr.is_none());
        assert_eq!(ctx.interface, "eth0");
    }
}
