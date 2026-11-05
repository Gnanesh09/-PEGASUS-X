import threading
from .agents import SCENARIOS, build_graph, run_fallback
from .store import add_event
from .lab_tests import lab_configuration

class SimulationEngine:
    def __init__(self):
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.worker = None
        self.running = False
        self.round_no = 0
        self.max_rounds = 10
        self.interval = 3
        self.mode = "simulation"
        self.graph, self.graph_status = build_graph()
        self.last_report = None
        self.last_error = None

    def status(self):
        with self.lock:
            return {"running": self.running, "round": self.round_no,
                    "max_rounds": self.max_rounds, "mode": self.mode,
                    "graph_status": self.graph_status, "last_report": self.last_report,
                    "last_error": self.last_error}

    def start(self, max_rounds=10, interval=3, mode="simulation"):
        with self.lock:
            if self.running:
                return False, "A simulation is already running."
            if mode not in ("simulation", "real_lab"):
                return False, "Unknown mode."
            if mode == "real_lab":
                ok, message = lab_configuration()
                if not ok:
                    return False, message
            self.stop_event.clear()
            self.round_no = 0
            self.max_rounds = max(1, min(int(max_rounds), 100))
            self.interval = max(1, min(int(interval), 60))
            self.mode = mode
            self.last_error = None
            self.running = True
            self.worker = threading.Thread(target=self._run, daemon=True)
            self.worker.start()
            return True, "Started."

    def stop(self):
        self.stop_event.set()
        return True

    def _run(self):
        try:
            for n in range(1, self.max_rounds + 1):
                if self.stop_event.is_set():
                    break
                self.round_no = n
                scenario = SCENARIOS[(n - 1) % len(SCENARIOS)]
                state = {"round_no": n, "scenario": scenario, "mode": self.mode}
                add_event(n, "Orchestrator", "orchestration", "info",
                          f"Started {self.mode} round {n}: {scenario['name']}",
                          {"scenario_id": scenario["id"], "mode": self.mode})
                if self.graph:
                    try:
                        result = self.graph.invoke(state, {"configurable": {"thread_id": f"pegasus-{self.mode}"}})
                    except Exception as exc:
                        self.last_error = f"LangGraph execution error: {type(exc).__name__}: {str(exc)[:160]}"
                        result = run_fallback(state)
                else:
                    result = run_fallback(state)
                self.last_report = result.get("report")
                add_event(n, "Orchestrator", "orchestration", "success",
                          f"Completed round {n}", {"score": result.get("evaluation", {}).get("score"),
                                                   "outcome": result.get("evaluation", {}).get("outcome")})
                if n < self.max_rounds and not self.stop_event.wait(self.interval):
                    continue
                break
        finally:
            with self.lock:
                self.running = False
