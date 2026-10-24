use super::AnalysisCore;

impl AnalysisCore {
    /// Adapter-scheduled passive maintenance. No timer or terminal is required.
    pub fn maintenance(&mut self) {
        self.scan_new_objects();
        self.maintenance_ticks = self.maintenance_ticks.wrapping_add(1);
        if self.maintenance_ticks % 30 == 0 {
            self.operator_graph.recompute_scores();
        }
        if self.maintenance_ticks % 60 == 0 {
            self.operator_graph.recompute_paths();
            self.operator_graph.recompute_clusters();
        }
    }

    /// Refresh all derived graph queries, e.g. at the end of an offline capture.
    pub fn refresh_graph(&mut self) {
        self.operator_graph.recompute_scores();
        self.operator_graph.recompute_paths();
        self.operator_graph.recompute_clusters();
    }
}
