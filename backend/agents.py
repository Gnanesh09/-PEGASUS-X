"""LangGraph workflow for safe simulation or bounded real PostgreSQL lab tests."""
import json, sqlite3, os
from typing import TypedDict
from .config import DB_PATH, GROQ_API_KEY, GROQ_MODEL
from .store import add_event, add_round
from .lab_tests import execute_lab_scenario

SCENARIOS = [
    {"id": "AUTH_BURST", "name": "Controlled authentication-failure test",
     "description": "Three intentional invalid-password attempts against the dedicated lab test role.",
     "severity": "high", "signals": ["3 fixed failed-login attempts", "dedicated lab role"],
     "expected": "Detect authentication failures without trying password lists."},
    {"id": "PRIVILEGE_CHECK", "name": "Restricted-table permission test",
     "description": "The restricted test role attempts one read-only SELECT on a table it must not access.",
     "severity": "medium", "signals": ["read-only SELECT", "restricted_demo", "pegasus_test"],
     "expected": "Observe PostgreSQL permission denial."},
    {"id": "QUERY_SPIKE", "name": "Bounded query-rate test",
     "description": "Twelve read-only SELECT queries run against a tiny synthetic table.",
     "severity": "medium", "signals": ["12 fixed SELECT queries", "read-only transaction"],
     "expected": "Measure actual query count and elapsed time."},
    {"id": "SCHEMA_ENUM", "name": "Read-only schema metadata test",
     "description": "The restricted test role reads a maximum of ten public table names from information_schema.",
     "severity": "low", "signals": ["information_schema.tables", "LIMIT 10", "read-only"],
     "expected": "Record the visible metadata objects without reading row data."}
]

class PegasusState(TypedDict, total=False):
    round_no: int
    scenario: dict
    mode: str
    red_event: dict
    detection: dict
    investigation: dict
    defense: dict
    evaluation: dict
    report: str


def _llm_note(system, user):
    if not GROQ_API_KEY:
        return None
    try:
        from langchain_groq import ChatGroq
        model = ChatGroq(api_key=GROQ_API_KEY, model=GROQ_MODEL, temperature=0)
        result = model.invoke([("system", system), ("human", user)])
        return str(result.content)[:1200]
    except Exception as exc:
        return f"LLM unavailable; deterministic agent continued ({type(exc).__name__})."


def red_team(state: PegasusState):
    s = state["scenario"]
    if state.get("mode") == "real_lab":
        observation = execute_lab_scenario(s["id"])
        event = {"scenario_id": s["id"], "scenario": s["name"],
                 "description": s["description"], "execution": observation.get("execution"),
                 "observed": observation.get("observed", False),
                 "target": "allowlisted pegasus_lab PostgreSQL VM", "observation": observation}
        severity = s["severity"] if observation.get("observed") else "warning"
        add_event(state["round_no"], "Red Team", "lab_test", severity,
                  f"{s['name']}: {observation.get('execution')}", event)
    else:
        event = {"scenario_id": s["id"], "scenario": s["name"],
                 "description": s["description"], "signals": s["signals"],
                 "execution": "SAFE_SIMULATED_TELEMETRY", "observed": False,
                 "target": "synthetic simulator"}
        add_event(state["round_no"], "Red Team", "simulation", s["severity"],
                  f"Generated simulated scenario: {s['name']}", event)
    return {"red_event": event}


def blue_team(state: PegasusState):
    e = state["red_event"]
    obs = e.get("observation", {})
    sid = e["scenario_id"]
    if state.get("mode") == "real_lab":
        if not e.get("observed"):
            detected, confidence = False, 0.0
            reason = obs.get("error", "Test did not return a real database observation.")
        elif sid == "AUTH_BURST":
            detected = obs.get("failed_auth_attempts", 0) >= 2
            confidence = .99 if detected else .10
            reason = f"Observed {obs.get('failed_auth_attempts', 0)} PostgreSQL authentication failures from three fixed attempts."
        elif sid == "PRIVILEGE_CHECK":
            denied = obs.get("permission_denied") is True
            detected, confidence = denied, (.98 if denied else .95)
            reason = "PostgreSQL denied the restricted role as expected." if denied else "Unexpected access: restricted role read the protected table."
            if not denied:
                confidence = .99
        elif sid == "QUERY_SPIKE":
            count, elapsed = obs.get("query_count", 0), obs.get("elapsed_ms", 999999)
            detected = count >= 10 and elapsed <= 5000
            confidence = .94 if detected else .35
            reason = f"Observed {count} SELECT statements in {elapsed} ms."
        else:
            count = obs.get("metadata_objects_seen", 0)
            detected = count > 0
            confidence = .86 if detected else .20
            reason = f"Observed {count} public metadata objects returned to the restricted role."
    else:
        confidence = {"AUTH_BURST": .98, "PRIVILEGE_CHECK": .96,
                      "QUERY_SPIKE": .91, "SCHEMA_ENUM": .84}.get(sid, .70)
        detected = True
        reason = "Matched deterministic simulation rule; no real database activity was performed."
    llm = _llm_note(
        "You are a defensive SOC analyst. Explain only supplied lab evidence. "
        "Do not suggest offensive commands or actions.", json.dumps(e)
    )
    detection = {"detected": detected, "confidence": confidence,
                 "rule": f"PEGASUS-{sid}", "evidence_source": e.get("execution"),
                 "explanation": llm or reason}
    add_event(state["round_no"], "Blue Team", "detection",
              "high" if confidence >= .95 else "medium" if detected else "warning",
              "Threat detected from database observation" if detected else "No verified detection; test was not observed or did not meet threshold.", detection)
    return {"detection": detection}


def threat_hunter(state: PegasusState):
    e, d = state["red_event"], state["detection"]
    obs = e.get("observation", {})
    mapping = {
        "AUTH_BURST": "Authentication failure monitoring (controlled validation; not a brute-force campaign)",
        "PRIVILEGE_CHECK": "Authorization boundary validation",
        "QUERY_SPIKE": "Database query-rate anomaly validation",
        "SCHEMA_ENUM": "Database metadata discovery validation"
    }
    investigation = {
        "verdict": "suspicious_lab_activity" if d["detected"] else "unconfirmed_or_test_failed",
        "security_mapping": mapping.get(e["scenario_id"], "Unmapped"),
        "evidence": obs if obs else {"mode": "simulation", "signals": state["scenario"]["signals"]},
        "correlation": f"{e['scenario_id']} evaluated by {d['rule']}",
        "confidence": d["confidence"]
    }
    add_event(state["round_no"], "Threat Hunter", "investigation", "medium",
              "Correlated observed database result and recorded the finding", investigation)
    return {"investigation": investigation}


def blue_defense(state: PegasusState):
    d = state["detection"]
    if state.get("mode") == "real_lab":
        # Real-mode response is an application-side stop/quarantine decision only.
        # It does not rewrite PostgreSQL roles or firewall rules.
        if d["detected"]:
            action = "Marked this test source/scenario as contained in PEGASUS-X and prevented destructive follow-up; no database permissions or host firewall were changed."
            status = "contained_in_app"
        else:
            action = "No containment applied because the test produced no verified detection; inspect the reported test error."
            status = "needs_review"
        defense = {"status": status, "action": action, "mode": "real_lab_observation",
                   "reversible": True, "database_modified": False}
    else:
        sid = state["red_event"]["scenario_id"]
        action = {
            "AUTH_BURST": "Marked simulated source for temporary containment.",
            "PRIVILEGE_CHECK": "Recorded the expected permission boundary.",
            "QUERY_SPIKE": "Recorded a simulated rate-limit response.",
            "SCHEMA_ENUM": "Raised simulated monitoring sensitivity."
        }.get(sid, "Recorded defensive observation.")
        defense = {"status": "contained" if d["detected"] else "needs_review",
                   "action": action, "mode": "simulation", "reversible": True}
    add_event(state["round_no"], "Blue Team", "defense", "success" if d["detected"] else "warning",
              defense["action"], defense)
    return {"defense": defense}


def analyst(state: PegasusState):
    d, inv, defense = state["detection"], state["investigation"], state["defense"]
    base = 40 * d["confidence"] + (30 if d["detected"] else 0)
    defense_points = 20 if defense["status"] in ("contained", "contained_in_app") else 0
    score = max(0, min(100, round(base + defense_points + 10)))
    outcome = "DETECTED" if d["detected"] else "NOT_DETECTED"
    if state.get("mode") == "real_lab" and not state["red_event"].get("observed"):
        outcome = "TEST_FAILED"
        score = 0
    report = {
        "round": state["round_no"], "mode": state.get("mode", "simulation"),
        "scenario": state["scenario"]["name"], "outcome": outcome,
        "score": score, "detection_confidence": d["confidence"],
        "red_team_execution": state["red_event"].get("execution"),
        "actual_observation": state["red_event"].get("observation"),
        "investigation": inv, "defense": defense,
        "limitations": ("Live lab mode performed bounded PostgreSQL checks. Response is application-side; no OS firewall or DB account changes are made."
                        if state.get("mode") == "real_lab" else
                        "Simulation mode generated synthetic telemetry; no real database attack traffic was sent.")
    }
    add_event(state["round_no"], "Security Analyst", "assessment", "success" if outcome == "DETECTED" else "warning",
              f"Round assessed: {outcome}; score {score}/100", report)
    add_round(state["round_no"], state["scenario"]["name"], outcome, score, json.dumps(report))
    return {"evaluation": report, "report": json.dumps(report, indent=2)}


def build_graph():
    try:
        from langgraph.graph import StateGraph, END
        from langgraph.checkpoint.sqlite import SqliteSaver
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        os.environ.setdefault("LANGGRAPH_STRICT_MSGPACK", "true")
        saver = SqliteSaver(conn)
        saver.setup()
        graph = StateGraph(PegasusState)
        graph.add_node("red_team", red_team)
        graph.add_node("blue_team", blue_team)
        graph.add_node("threat_hunter", threat_hunter)
        graph.add_node("blue_defense", blue_defense)
        graph.add_node("analyst", analyst)
        graph.set_entry_point("red_team")
        graph.add_edge("red_team", "blue_team")
        graph.add_edge("blue_team", "threat_hunter")
        graph.add_edge("threat_hunter", "blue_defense")
        graph.add_edge("blue_defense", "analyst")
        graph.add_edge("analyst", END)
        return graph.compile(checkpointer=saver), "LangGraph + SQLite persistent checkpoints"
    except Exception as exc:
        return None, f"LangGraph checkpoint unavailable; sequential fallback active ({type(exc).__name__})"


def run_fallback(state):
    state.update(red_team(state))
    state.update(blue_team(state))
    state.update(threat_hunter(state))
    state.update(blue_defense(state))
    state.update(analyst(state))
    return state
