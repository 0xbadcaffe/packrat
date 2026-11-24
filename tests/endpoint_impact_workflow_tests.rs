#![cfg(feature = "terminal-ui")]

use packrat_tui::{
    analysis::{
        impact::{EndpointCategory, EndpointEvidence, ImpactConfidence, correlate},
        incident::{Incident, IncidentSnapshot, IncidentSource, IncidentStatus},
    },
    app::{App, StartupMode},
    model::{
        evidence::Severity,
        project::{ProjectSaveMode, ProjectState},
    },
    storage::project_store,
};

#[test]
fn importing_endpoint_reports_after_opening_a_case_preserves_scoped_evidence() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("case.json");
    let report = root.path().join("endpoint.ndjson");
    let incident = Incident {
        id: 1,
        capture_id: Some("capture-a".into()),
        observation_path: None,
        target: "192.0.2.10".into(),
        source: IncidentSource::UserRule,
        detector: "Rule".into(),
        summary: "Finding".into(),
        severity: Severity::Critical,
        attacker: "192.0.2.12".into(),
        first_packet: 1,
        last_packet: 1,
        first_seen: 1.0,
        last_seen: 1.0,
        status: IncidentStatus::PendingReview,
        reviewed: false,
        packet_history: Vec::new(),
    };
    let event = |category, scope, evidence_id: &str, subject: &str| EndpointEvidence {
        incident_id: incident.id,
        capture_id: scope,
        target: incident.target.clone(),
        source: "audit".into(),
        evidence_id: evidence_id.into(),
        category,
        subject: subject.into(),
        action: "observed".into(),
        successful: true,
    };
    let capture = incident.capture_id.clone();
    let mut state = ProjectState::new("Case", ProjectSaveMode::Lightweight);
    state.incident_state = Some(IncidentSnapshot {
        incidents: vec![incident.clone()],
        last_id: 1,
    });
    state.endpoint_evidence.push(event(
        EndpointCategory::File,
        capture.clone(),
        "1",
        "/srv/record",
    ));
    let mut incomplete = event(EndpointCategory::Data, capture.clone(), "old", "unsubstantiated report");
    incomplete.action.clear();
    state.endpoint_evidence.push(incomplete);
    project_store::save(&state, &project).unwrap();
    let input = [
        event(
            EndpointCategory::Capability,
            capture,
            "2",
            "privilege change",
        ),
        event(EndpointCategory::Data, None, "3", "legacy report"),
        event(
            EndpointCategory::File,
            Some("capture-b".into()),
            "4",
            "/other/capture",
        ),
    ]
    .iter()
    .map(|event| serde_json::to_string(event).unwrap())
    .collect::<Vec<_>>()
    .join("\n");
    std::fs::write(&report, input).unwrap();

    let (tx, _) = tokio::sync::mpsc::channel(1);
    let mut app = App::new_with_mode(tx, StartupMode::OfflineReview);
    app.start_background_analysis().unwrap();
    app.open_project(&project).unwrap();
    app.load_endpoint_evidence(&report);
    app.load_endpoint_evidence(&report);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !app.analysis_idle() {
        app.poll_analysis();
        assert!(std::time::Instant::now() < deadline, "analysis did not drain");
        std::thread::yield_now();
    }
    app.query_core(|core| {
        assert_eq!(core.endpoint_evidence.len(), 5);
        let impact = correlate(core.incidents.active().unwrap(), &core.endpoint_evidence);
        assert_eq!(impact.invalid_endpoint_reports, 1);
        let observed: Vec<_> = impact
            .evidence
            .iter()
            .filter(|evidence| evidence.confidence == ImpactConfidence::Observed)
            .map(|evidence| evidence.subject.as_str())
            .collect();
        assert_eq!(observed, ["/srv/record", "privilege change"]);
        assert!(!impact.compromise_confirmed);
    })
    .unwrap();
    app.stop_background_analysis().unwrap();
}
