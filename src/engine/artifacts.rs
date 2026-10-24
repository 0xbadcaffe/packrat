use super::AnalysisCore;

impl AnalysisCore {
    /// Scan at most four retained objects per maintenance step.
    pub fn scan_new_objects(&mut self) -> usize {
        if self.yara_engine.rules.is_empty() {
            return 0;
        }
        let start = self.yara_scan_cursor;
        let end = start.saturating_add(4).min(self.carved_objects.len());
        if start >= end {
            return 0;
        }
        for object in &mut self.carved_objects[start..end] {
            let result = self.yara_engine.scan_target(
                &object.data[..object.data.len().min(1_048_576)],
                object.id,
                "object",
                &format!("#{} {}", object.id, object.kind),
            );
            object.yara_hits = result.rule_names();
            if !result.matches.is_empty() {
                self.yara_engine.results.push(result);
            }
        }
        self.yara_scan_cursor = end;
        end - start
    }

    pub fn reset_object_scan(&mut self) {
        self.yara_engine.clear_results();
        self.yara_scan_cursor = 0;
        for object in &mut self.carved_objects {
            object.yara_hits.clear();
        }
    }

    /// Carve retained contiguous bytes in place; no full-stream copies or file IO.
    /// Candidates are byte signatures, not proof of a complete transferred file.
    pub fn carve_from_streams(&mut self) {
        for stream in self.streams.all() {
            let id = stream.key.id();
            for (data, suffix) in [(&stream.client_data, "A->B"), (&stream.server_data, "B->A")] {
                let objects = self.carver.carve(data, &format!("{id} {suffix}"));
                for object in &objects {
                    self.operator_graph.on_carved_object(
                        object.id,
                        &object.kind,
                        &object.sha256,
                        &object.source,
                        object.data.len(),
                        stream.last_seen,
                    );
                }
                self.carved_objects.extend(objects);
            }
        }
    }
}
