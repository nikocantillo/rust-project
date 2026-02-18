// src/main.rs
mod db;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

// ====== API models ======

#[derive(Debug, Deserialize)]
struct QueryRequest {
    tenant_id: String,
    user_id: String,
    roles: Vec<String>,
    department: Option<String>,
    region: Option<String>,
    query: String,
}

#[derive(Debug, Serialize, Clone)]
struct Citation {
    doc_id: String,
    chunk_id: String,
}

#[derive(Debug, Serialize)]
struct QueryResponse {
    run_id: String,
    decision: String,
    answer: String,
    citations: Vec<Citation>,
}

#[derive(Debug, Serialize, Clone)]
struct AuditEvent {
    event_type: String, // ROUTER|POLICY|RETRIEVAL|COMPLIANCE|RESPONSE
    payload: serde_json::Value,
    ts_unix_ms: i64,
}

#[derive(Debug, Serialize, Clone)]
struct RunAudit {
    run_id: String,
    tenant_id: String,
    user_id: String,
    query: String,
    decision: String,
    events: Vec<AuditEvent>,
}

#[derive(Clone)]
struct AppState {
    // Por ahora no guardamos auditoría en memoria: va a ADW
    // Luego aquí irá un pool/config si quieres.
}

// ====== Handlers ======

async fn health() -> &'static str {
    "ok"
}

/// Policy súper simple (RBAC): permite si el usuario tiene al menos uno de estos roles.
fn policy_allow(roles: &[String]) -> bool {
    let allowed = ["admin", "rag_user", "compliance"];
    roles.iter().any(|r| allowed.contains(&r.as_str()))
}

/// “Router agent” (stub): decide tópico según keywords.
fn router_topic(query: &str) -> &'static str {
    let q = query.to_lowercase();
    if q.contains("vacacion") || q.contains("beneficio") || q.contains("hr") {
        "HR"
    } else if q.contains("legal") || q.contains("contrato") || q.contains("clausula") {
        "LEGAL"
    } else {
        "GENERAL"
    }
}

/// “Retriever agent” (stub): no hacemos retrieval real (aún).
fn retrieval_stub(_tenant_id: &str, _topic: &str) -> Vec<Citation> {
    vec![Citation {
        doc_id: "doc_demo_001".to_string(),
        chunk_id: "chunk_0007".to_string(),
    }]
}

/// “Compliance agent” (stub): exige que haya citas para permitir una respuesta “con evidencia”.
fn compliance_check(citations: &[Citation]) -> bool {
    !citations.is_empty()
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs() as i64) * 1000 + (d.subsec_millis() as i64)
}

async fn query_handler(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<QueryRequest>,
) -> Response {
    let run_id = Uuid::new_v4().to_string();
    let ts = now_ms();

    // ===== Router agent =====
    let topic = router_topic(&req.query);
    let router_event = AuditEvent {
        event_type: "ROUTER".to_string(),
        payload: serde_json::json!({
            "topic": topic,
            "department": req.department,
            "region": req.region
        }),
        ts_unix_ms: ts,
    };

    // ===== Policy agent =====
    let allowed = policy_allow(&req.roles);
    let policy_event = AuditEvent {
        event_type: "POLICY".to_string(),
        payload: serde_json::json!({
            "result": if allowed { "ALLOW" } else { "DENY" },
            "roles": req.roles
        }),
        ts_unix_ms: now_ms(),
    };

    // ===== Caso DENY =====
    if !allowed {
        warn!(
            run_id = %run_id,
            tenant_id = %req.tenant_id,
            user_id = %req.user_id,
            "policy=deny"
        );

        let audit = RunAudit {
            run_id: run_id.clone(),
            tenant_id: req.tenant_id.clone(),
            user_id: req.user_id.clone(),
            query: req.query.clone(),
            decision: "DENY".to_string(),
            events: vec![router_event, policy_event],
        };

        // Persistencia en ADW (bloqueante -> spawn_blocking)
        let audit_clone = audit.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = crate::db::insert_audit(&audit_clone) {
                eprintln!("failed to persist audit (DENY): {e}");
            }
        });

        let resp = QueryResponse {
            run_id,
            decision: "DENY".to_string(),
            answer: "No tienes permisos para consultar este sistema.".to_string(),
            citations: vec![],
        };

        return (StatusCode::FORBIDDEN, Json(resp)).into_response();
    }

    // ===== Retriever agent (stub) =====
    let citations = retrieval_stub(&req.tenant_id, topic);
    let retrieval_event = AuditEvent {
        event_type: "RETRIEVAL".to_string(),
        payload: serde_json::json!({
            "citations": citations
        }),
        ts_unix_ms: now_ms(),
    };

    // ===== Compliance agent (stub) =====
    let ok_evidence = compliance_check(&citations);
    let compliance_event = AuditEvent {
        event_type: "COMPLIANCE".to_string(),
        payload: serde_json::json!({
            "evidence_required": true,
            "passed": ok_evidence
        }),
        ts_unix_ms: now_ms(),
    };

    let (decision, answer, status) = if ok_evidence {
        (
            "ALLOW".to_string(),
            format!("(stub) Topic={} | Respuesta con evidencia para: {}", topic, req.query),
            StatusCode::OK,
        )
    } else {
        (
            "DENY".to_string(),
            "No encontré evidencia suficiente en documentos permitidos.".to_string(),
            StatusCode::OK,
        )
    };

    let response_event = AuditEvent {
        event_type: "RESPONSE".to_string(),
        payload: serde_json::json!({
            "decision": decision,
        }),
        ts_unix_ms: now_ms(),
    };

    info!(
        run_id = %run_id,
        tenant_id = %req.tenant_id,
        user_id = %req.user_id,
        topic = %topic,
        "query=processed"
    );

    let audit = RunAudit {
        run_id: run_id.clone(),
        tenant_id: req.tenant_id.clone(),
        user_id: req.user_id.clone(),
        query: req.query.clone(),
        decision: decision.clone(),
        events: vec![router_event, policy_event, retrieval_event, compliance_event, response_event],
    };

    // Persistencia en ADW
    let audit_clone = audit.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = crate::db::insert_audit(&audit_clone) {
            eprintln!("failed to persist audit (ALLOW): {e}");
        }
    });

    let resp = QueryResponse {
        run_id,
        decision,
        answer,
        citations,
    };

    (status, Json(resp)).into_response()
}

async fn audit_run_handler(
    State(_state): State<Arc<AppState>>,
    Path(run_id): Path<String>,
) -> Response {
    // DB call es bloqueante -> spawn_blocking
    let result = tokio::task::spawn_blocking(move || crate::db::load_audit(&run_id)).await;

    match result {
        Ok(Ok(Some(audit))) => (StatusCode::OK, Json(audit)).into_response(),
        Ok(Ok(None)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error":"run_id not found"})),
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db error: {e}")})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("join error: {e}")})),
        )
            .into_response(),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state = Arc::new(AppState {});

    let app = Router::new()
        .route("/health", get(health))
        .route("/query", post(query_handler))
        .route("/audit/run/{run_id}", get(audit_run_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("failed to bind");

    info!("listening on http://localhost:8080");
    axum::serve(listener, app).await.unwrap();
}
