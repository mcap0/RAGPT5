import os
import json
import time
import uuid
import traceback
from flask import Flask, request, jsonify, render_template, Response, stream_with_context
from agents import (
    agent_preprocess,
    agent_identify,
    agent_retrieve,
    agent_generate,
    agent_verify
)

APP_NAME = "RAGPT5"
MODEL = os.getenv("MODEL", "gpt-5")
MAX_ITER = int(os.getenv("MAX_ITER", "3"))
MAX_CALLS = int(os.getenv("MAX_CALLS", "12"))
STOP_REQUESTED = False

app = Flask(__name__)

def overdo(state):
    hit = state["complete"] \
          or state["n_calls"] >= state.get("max_calls", MAX_CALLS) or state["n_iter"] >= state.get("max_iter", MAX_ITER)
    if hit:
        state["complete"] = True
    return hit
    
def load_environment_data(env_name):
    filename = f"data/{env_name}.txt"
    if not os.path.exists(filename):
        raise FileNotFoundError(f"File {filename} non trovato")
    with open(filename, "r", encoding="utf-8") as f:
        return f.read()

def init_state(text, environment, env_data=""):
    return {
        "id": str(uuid.uuid4()),
        "env": environment,
        "env_data": env_data,
        "input_text": text,
        "text_preproc": None,
        "is_nlacp": None,
        "env_var": {"subjects": [], "actions": [], "resources": [], "purposes": [], "conditions": []},
        "policy_json": {"dsarcp": []},
        "verifier_output": {"status": "unknown", "error": ""},
        "has_verified": False,
        "n_iter": 0,
        "n_calls": 0,
        "max_iter": MAX_ITER,     
        "max_calls": MAX_CALLS,   
        "complete": False,
        "feedback": None
    }

def finish_payload(state, start_time):
    elapsed = int((time.time() - start_time) * 1000)
    return {
        "dsarcp": state.get("policy_json", {}).get("dsarcp", []),
        "verifier_output": state.get("verifier_output"),
        "n_iter": state.get("n_iter"),
        "n_calls": state.get("n_calls"),
        "complete": state.get("complete"),
        "env": state.get("env"),
        "id": state.get("id"),
        "elapsed_ms": elapsed
    }

def sse(event, data):
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"

@app.route("/", methods=["GET"])
def index():
    return render_template(
        "index.html",
        app_name=APP_NAME,
        model=MODEL,
        max_iter=MAX_ITER,
        max_calls=MAX_CALLS
    )

@app.route("/api/generate", methods=["POST"])
def generate_policy():
    start_time = time.time()
    try:
        data = request.get_json(force=True)
        text = (data.get("text") or "").strip()
        environment = (data.get("environment") or "").strip().lower()

        if not environment:
            return jsonify({"error": "environment is required"}), 400
        if not text:
            return jsonify({"error": "text is required"}), 400

        try:
            env_data = load_environment_data(environment)
        except FileNotFoundError as e:
            return jsonify({"error": str(e)}), 404

        state = init_state(text, environment, env_data)

        # Step 1
        state = agent_preprocess(state)
        if overdo(state): 
            return jsonify(finish_payload(state, start_time))

        # Step 2
        state = agent_identify(state)
        if overdo(state): 
            return jsonify(finish_payload(state, start_time))
        if state.get("is_nlacp") is False:
            state["verifier_output"] = {"status": "correct", "error": ""}
            return jsonify(finish_payload(state, start_time))

        # Step 3
        state = agent_retrieve(state)
        if overdo(state): 
            return jsonify(finish_payload(state, start_time))

        # Step 4
        state = agent_generate(state, attack=attack)
        if overdo(state): 
            return jsonify(finish_payload(state, start_time))

        # Step 5–6
        while True:
            state = agent_verify(state)
            if overdo(state): 
                break

            if (state.get("verifier_output", {}).get("status", "").strip().lower() == "correct"):
                break

            if state["n_iter"] >= state.get("max_iter", MAX_ITER):
                state["complete"] = True
                break

            state = agent_generate(state, attack=attack)
            if overdo(state): 
                break

        return jsonify(finish_payload(state, start_time))
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/log", methods=["GET"])
def log():
    text = (request.args.get("text") or "").strip()
    env = (request.args.get("environment") or "").strip().lower()
    attack_raw = (request.args.get("attack") or "false").strip().lower()
    attack = attack_raw in ("1", "true", "yes", "on")

    if not env:
        return Response(sse("error", {"error": "environment is required"}), mimetype="text/event-stream")
    if not text:
        return Response(sse("error", {"error": "text is required"}), mimetype="text/event-stream")

    try:
        env_data = load_environment_data(env)
    except FileNotFoundError as e:
        return Response(sse("error", {"error": str(e)}), mimetype="text/event-stream")

    def generate():
        global STOP_REQUESTED
        STOP_REQUESTED = False
        start_time = time.time()
        state = init_state(text, env, env_data)
        logs = []

        def log(event):
            event["time"] = int(time.time() * 1000)
            event["iter"] = state["n_iter"]
            event["calls"] = state["n_calls"]
            logs.append(event)

        def flush():
            nonlocal logs
            while logs:
                yield sse("log", logs.pop(0))

        yield sse("log", {"msg": "start", "id": state["id"], "env": env})

        # Step 1
        log({"step": 1, "phase": "start", "msg": "pre-processing"})
        state = agent_preprocess(state, logger=log)
        yield from flush()
        log({"step": 1, "phase": "end", "text_preproc": state.get("text_preproc")})
        yield from flush()
        if overdo(state):
            payload = finish_payload(state, start_time)
            yield sse("done", payload)
            return

        # Step 2
        log({"step": 2, "phase": "start", "msg": "identify"})
        state = agent_identify(state, logger=log)
        yield from flush()
        log({"step": 2, "phase": "end", "is_nlacp": state.get("is_nlacp")})
        yield from flush()
        if state.get("is_nlacp") is False:
            payload = finish_payload(state, start_time)
            yield sse("done", payload)
            return

        # Step 3
        log({"step": 3, "phase": "start", "msg": "retrieving domain info"})
        state = agent_retrieve(state, logger=log)
        yield from flush()
        log({"step": 3, "phase": "end", "env_var": state["env_var"]})
        yield from flush()

        # Step 4
        log({"step": 4, "phase": "start", "msg": "generating policy"})
        state = agent_generate(state, logger=log)
        yield from flush()
        log({"step": 4, "phase": "end", "rules_count": len(state.get("policy_json", {}).get("dsarcp", []))})
        log({"event": "policy_preview","dsarcp": state.get("policy_json", {}).get("dsarcp", [])[:3]})
        yield from flush()

        # Step 5–6
        while True:
            log({"step": 5, "phase": "start", "msg": "verify"})
            state = agent_verify(state, logger=log)
            yield from flush()
            log({"step": 5, "phase": "end", "verifier_output": state.get("verifier_output")})
            yield from flush()

            if overdo(state):
                break
            if (state.get("verifier_output", {}).get("status", "").strip().lower() == "correct"):
                break
            if state["n_iter"] >= state.get("max_iter", MAX_ITER):
                break
            if state["n_calls"] >= MAX_CALLS:
                state["complete"] = True
                break

            log({"step": 6, "phase": "start", "msg": "refine"})
            state = agent_generate(state, logger=log)
            yield from flush()
            log({"step": 6, "phase": "end", "n_iter": state["n_iter"]})
            yield from flush()
            if overdo(state): break

        payload = finish_payload(state, start_time)
        yield sse("result", payload)
        yield sse("done", payload)

    return Response(stream_with_context(generate()), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no"
    })

@app.route("/api/stop", methods=["POST"])
def stop():
    global STOP_REQUESTED
    STOP_REQUESTED = True
    return jsonify({"status": "stopped"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
