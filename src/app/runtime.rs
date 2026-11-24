use super::*;
use crate::{analysis::telemetry::CaptureCounters, capture::CaptureTask};

impl App {
    /// Inject a crafted packet into the live packet list.
    pub fn craft_inject(&mut self) {
        let next_no = self.packet_counter + 1;
        match self.craft.build_packet(next_no) {
            Ok(pkt) => {
                let label = format!(
                    "Injected #{} — {} {} → {}",
                    next_no, pkt.protocol, pkt.src, pkt.dst
                );
                self.craft.result = Some(Ok(label));
                self.inject_packet(pkt);
            }
            Err(e) => {
                self.craft.result = Some(Err(e));
            }
        }
    }

    pub fn tick(&mut self) {
        self.poll_analysis();
        self.poll_alert_saving(Instant::now());
        self.poll_alert_case_export();
        let mut archive_failed = false;
        if let Some(archive) = self.packet_archive.as_mut()
            && let Some(error) = archive.poll_error()
        {
            archive_failed = true;
            if archive.alert_evidence_only() {
                self.set_status(format!("Alert packet archive write failed: {error}; capture continues"));
            } else {
                self.abort_capture();
                self.capturing = false;
                self.set_status(format!("Capture stopped: archive write failed: {error}"));
            }
        }
        if let Some(reason) = self
            .packet_archive
            .as_mut()
            .and_then(|archive| archive.take_pause_notice())
            && !archive_failed
        {
            self.set_status(format!("Archive paused: {reason}; capture and analysis are unaffected"));
        }
        if let Some(result) = self.capture_handle.as_mut().and_then(|task| task.result()) {
            self.capture_handle = None;
            self.capturing = false;
            self.set_status(match result {
                Ok(()) => "Capture stopped".into(),
                Err(error) => error,
            });
        }
        self.rate_tick += 1;

        // Flood mode — inject packets from the crafter
        let source_ready = !self.analysis_backpressured();
        let flood_n = self
            .craft
            .flood_tick_budget(if source_ready { 256 } else { 0 });
        for i in 0..flood_n {
            let next_no = self.packet_counter + 1 + i as u64;
            if let Ok(pkt) = self.craft.build_packet(next_no) {
                self.craft.flood_sent += 1;
                self.inject_packet(pkt);
            }
        }

        // Advance traceroute simulation one hop at a time
        self.traceroute.tick();

        // Advance port scanner
        if self.scan.running {
            self.scan.tick();
        }

        if self.rate_tick % 20 == 1 {
            let _ = self.socket_scope.refresh_event_file();
            let _ = self.socket_scope.refresh();
            self.configure_core(|core| {
                if core.tls_tracker.key_shelf.path.is_some() {
                    let _ = core.tls_tracker.reload_key_log();
                }
            });
        }

        // Advance PCAP replay — inject replayed packets
        let replayed = if source_ready {
            self.replay.tick()
        } else {
            Vec::new()
        };
        for pkt in replayed {
            self.ingest_packet_inner(pkt);
        }

        if self.capturing {
            if rand::random::<u8>() % 3 == 0 {
                let entry = crate::sim::dynamic::generate_entry(self.rate_tick);
                self.dyn_log.push(entry);
                if self.dyn_log.len() > 500 {
                    self.dyn_log.remove(0);
                }
            }
        }

        if self.rate_tick % 10 == 0 {
            self.rate_history.push(self.rate_this_sec);
            self.rate_history.remove(0);
            self.rate_this_sec = 0;
        }

        // Expire transient status message
        if self.status_msg_ticks > 0 {
            self.status_msg_ticks -= 1;
            if self.status_msg_ticks == 0 {
                self.status_msg = None;
            }
        }

        if self.rate_tick % 10 == 0 && self.pending_analysis.len() < 8 {
            self.configure_core(|core| core.maintenance());
        }
        self.refresh_telemetry();
        if self.preferences_dirty.get() {
            self.save_preferences();
        }
    }

    pub(crate) fn animation_tick(&self) -> u32 {
        self.rate_tick
    }

    pub(crate) fn pcap_buffer_drops(&self) -> Option<u32> {
        self.capture_handle.as_ref()?.pcap_buffer_drops()
    }

    pub(super) fn refresh_telemetry(&self) {
        let capacity = self.packet_tx.max_capacity();
        let queue = crate::analysis::telemetry::CaptureQueueTelemetry {
            depth: capacity.saturating_sub(self.packet_tx.capacity()),
            capacity,
            dispatch_waiting: self.capture_dispatch_waiting,
            analysis_packets_pending: self.packet_effects.len(),
        };
        let run_id = self.capture_handle.as_ref().map(CaptureTask::run_id);
        let counters = CaptureCounters {
            pcap_buffer_drops: self.pcap_buffer_drops(),
            truncated_frames: self.capture_handle.as_ref().and_then(CaptureTask::truncated_frames),
            queue_full_packets: self.capture_handle.as_ref().and_then(CaptureTask::queue_full_packets),
        };
        if !self.analysis_generation_ready() {
            self.telemetry.publish_capture_health(run_id, queue, counters);
            return;
        }
        let core_handle = self.core.clone();
        let Ok(Some(core)) = core_handle.try_read() else {
            self.telemetry.publish_capture_health(run_id, queue, counters);
            return;
        };
        let archive_pause_reason = self.packet_archive.as_ref().and_then(|archive| archive.pause_code());
        self.telemetry.publish(TelemetrySnapshot {
            packets_total: self.packet_counter,
            bytes_total: self.total_bytes,
            visible_packets: self.filtered.len(),
            flows: core.flow_tracker.len(),
            flow_summary_evictions: core.flow_tracker.evicted(),
            tcp_stream_cache: Some(crate::analysis::telemetry::TcpStreamCacheTelemetry {
                retained_streams: core.streams.len(),
                evicted_streams: core.streams.evicted_streams(),
            }),
            dns_capacity: Some(core.security.dns_capacity_stats()),
            hosts: core.hosts.len(),
            security_findings: core.security.alert_count(),
            rule_hits: core.rule_engine.hits.len(),
            ioc_hits: core.ioc_engine.hit_count(),
            pending_incidents: core
                .incidents
                .incidents
                .iter()
                .filter(|incident| {
                    incident.status == crate::analysis::incident::IncidentStatus::PendingReview
                })
                .count(),
            evidence_exports: self.evidence_vault.exports.len(),
            packets_per_second: self.current_rate(),
            capturing: self.capturing,
            capture_run_id: run_id,
            capture_interface: (self.capturing && self.capture_handle.is_some())
                .then(|| self.selected_iface.clone()),
            capture_link_type: self.capture_handle.as_ref().and_then(crate::capture::CaptureTask::link_type),
            capture_id: self.capture_id.clone(),
            alert_session_id: Some(self.alert_session_id.clone()),
            capture_queue: queue,
            pcap_buffer_drops: counters.pcap_buffer_drops,
            capture_truncated_frames: counters.truncated_frames,
            capture_queue_full_packets: counters.queue_full_packets,
            alert_saving: self.save_alerts && core.alert_jsonl_writer.is_some(),
            alert_save_failed: self.save_alerts && core.alert_save_error.is_some(),
            alert_save_failures: core.alert_save_failures,
            alert_save_backlog_dropped: core.alert_write_backlog.dropped,
            archive_enabled: self.packet_archive.is_some(),
            archive_paused: archive_pause_reason.is_some(),
            archive_pause_reason,
            archive_usage: self.packet_archive.as_ref().and_then(|archive| archive.usage()),
            archive_alert_evidence_only: self.packet_archive.as_ref().is_some_and(|archive| archive.alert_evidence_only()),
            archive_evidence_rules: core.alert_center.archive_evidence_rules.clone(),
            latency_p95_ms: self.wire_pulse.p95_ms().unwrap_or(0.0),
            enriched_addresses: self.net_registry.observed.len(),
        });
    }
}

#[cfg(all(test, feature = "real-capture"))]
#[path = "../../tests/unit/app_capture_health_tests.rs"]
mod tests;
