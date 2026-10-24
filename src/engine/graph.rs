use std::collections::HashMap;

use super::AnalysisCore;
use crate::net::packet::Packet;

impl AnalysisCore {
    /// Rebuild derived correlations from retained records, e.g. after loading
    /// synthetic scenario seeds. Missing endpoint context is not guessed.
    pub fn rebuild_retained_graph<'a>(&mut self, packets: impl IntoIterator<Item = &'a Packet>) {
        self.operator_graph.clear();
        let mut context = HashMap::new();
        for packet in packets {
            if Self::disposition(packet) != super::PacketDisposition::Analyzed {
                continue;
            }
            self.operator_graph.on_packet(
                &packet.src,
                &packet.dst,
                &packet.protocol,
                packet.src_port,
                packet.dst_port,
                packet.timestamp,
                packet.length as u64,
                packet.no,
            );
            context.insert(
                packet.no,
                (packet.src.as_str(), packet.dst.as_str(), packet.timestamp),
            );
        }
        for alert in &self.security.ids_alerts {
            let &(src, dst, timestamp) = context.get(&alert.pkt_no).unwrap_or(&("", "", 0.0));
            self.operator_graph.on_ids_alert(
                alert.signature,
                &alert.severity.to_string(),
                src,
                dst,
                alert.pkt_no,
                timestamp,
            );
        }
        for hit in &self.ioc_engine.hits {
            let src = context.get(&hit.pkt_no).map_or("", |entry| entry.0);
            self.operator_graph.on_ioc_hit(
                &hit.ioc.value,
                &hit.ioc.kind.to_string(),
                &hit.context,
                hit.pkt_no,
                hit.ts,
                src,
            );
        }
        for credential in &self.credentials {
            let &(src, dst, timestamp) = context.get(&credential.pkt_no).unwrap_or(&("", "", 0.0));
            self.operator_graph.on_credential(
                Some(credential.kind),
                &credential.proto,
                true,
                src,
                dst,
                timestamp,
                credential.pkt_no,
            );
        }
        for hit in &self.rule_engine.hits {
            self.operator_graph.on_rule_hit(
                &hit.rule_id,
                &hit.rule_name,
                &hit.message,
                hit.pkt_no,
                hit.ts,
            );
        }
        for object in &self.carved_objects {
            self.operator_graph.on_carved_object(
                object.id,
                &object.kind,
                &object.sha256,
                &object.source,
                object.data.len(),
                0.0,
            );
        }
        self.refresh_graph();
    }
}
