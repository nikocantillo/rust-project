use oracle::{Connection, Error as OracleError};
use std::env;

use crate::{AuditEvent, RunAudit};

fn get_conn() -> Result<Connection, OracleError> {
    let user = env::var("ORACLE_USER").expect("ORACLE_USER not set");
    let pass = env::var("ORACLE_PASSWORD").expect("ORACLE_PASSWORD not set");
    let conn = env::var("ORACLE_CONNECT").expect("ORACLE_CONNECT not set");
    Connection::connect(user, pass, conn)
}

pub fn insert_audit(run: &RunAudit) -> Result<(), OracleError> {
    let conn = get_conn()?;

    // execute() espera params: &[&dyn ToSql]
    conn.execute(
        "INSERT INTO AUDIT_RUNS (RUN_ID, TENANT_ID, USER_ID, QUERY_TEXT, DECISION)
         VALUES (:1, :2, :3, :4, :5)",
        &[
            &run.run_id,
            &run.tenant_id,
            &run.user_id,
            &run.query,
            &run.decision,
        ],
    )?;

    for ev in &run.events {
        let event_id = uuid::Uuid::new_v4().to_string();
        let payload_str = ev.payload.to_string();

        conn.execute(
            "INSERT INTO AUDIT_EVENTS (EVENT_ID, RUN_ID, EVENT_TYPE, PAYLOAD_JSON, TS_UNIX_MS)
             VALUES (:1, :2, :3, :4, :5)",
            &[
                &event_id,
                &run.run_id,
                &ev.event_type,
                &payload_str,
                &ev.ts_unix_ms,
            ],
        )?;
    }

    conn.commit()?;
    Ok(())
}

pub fn load_audit(run_id: &str) -> Result<Option<RunAudit>, OracleError> {
    let conn = get_conn()?;

    // Si no existe el RUN_ID, oracle devuelve Error::NoDataFound
    let row = match conn.query_row(
    "SELECT TENANT_ID, USER_ID, QUERY_TEXT, DECISION
     FROM AUDIT_RUNS
     WHERE RUN_ID = :1",
    &[&run_id],
    ) {
        Ok(r) => r,
        Err(e) if matches!(e.kind(), oracle::ErrorKind::NoDataFound) => return Ok(None),
        Err(e) => return Err(e),
    };

    let tenant_id: String = row.get(0)?;
    let user_id: String = row.get(1)?;
    let query: String = row.get(2)?;
    let decision: String = row.get(3)?;

    let rows = conn.query(
        "SELECT EVENT_TYPE, PAYLOAD_JSON, TS_UNIX_MS
         FROM AUDIT_EVENTS
         WHERE RUN_ID = :1
         ORDER BY CREATED_AT",
        &[&run_id],
    )?;

    let mut events: Vec<AuditEvent> = Vec::new();
    for r in rows {
        let r = r?;
        let event_type: String = r.get(0)?;
        let payload_json: String = r.get(1)?;
        let ts_unix_ms: i64 = r.get(2)?;

        let payload: serde_json::Value =
            serde_json::from_str(&payload_json)
                .unwrap_or_else(|_| serde_json::json!({"_raw": payload_json}));

        events.push(AuditEvent {
            event_type,
            payload,
            ts_unix_ms,
        });
    }

    Ok(Some(RunAudit {
        run_id: run_id.to_string(),
        tenant_id,
        user_id,
        query,
        decision,
        events,
    }))
}
