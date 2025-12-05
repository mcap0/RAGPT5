import os
import json
from openai import OpenAI
from tools import ensure_policy_parameters, ensure_sar


MODEL = os.getenv("MODEL", "gpt-5")

from prompts import (
    SYS_PREPROCESS,
    SYS_IDENTIFY,
    SYS_RETRIEVE,
    SYS_GENERATE,
    SYS_VERIFY,
    SYS_REFINE
)

client = OpenAI()


def check_limits(state):
    if state["n_calls"] >= state.get("max_calls", 12) or state["n_iter"] > state.get("max_iter", 3):
        state["complete"] = True
        return True
    return False

def call_model(state, messages, logger=None):
    if check_limits(state):
        return None

    state["n_calls"] += 1

    if logger:
        logger({
            "event": "llm_call_start",
            "model": MODEL,
            "messages": len(messages),
            "sys_len": len(messages[0]["content"]) if messages and messages[0]["role"]=="system" else 0,
            "user_len": sum(len(m.get("content","")) for m in messages if m.get("role")=="user")
        })

    try:
        response = client.chat.completions.create(
            model=MODEL,
            response_format={"type": "json_object"},
            messages=messages
        )

        if logger and getattr(response, "usage", None):
            usage = response.usage
            logger({
                "event":"llm_call_usage",
                "prompt_tokens":getattr(usage,"prompt_tokens",None),
                "completion_tokens":getattr(usage,"completion_tokens",None),
                "total_tokens":getattr(usage,"total_tokens",None)
            })

        if not getattr(response, "choices", None) or not response.choices:
            if logger: logger({"event":"empty_completion"})
            state["complete"] = True
            return None

        msg = response.choices[0].message
        content = (msg.content or "")

        if logger:
            logger({"event": "llm_call_preview", "response_head": content[:200]})

        try:
            result = json.loads(content) if content else {}
        except Exception:
            if logger:
                logger({"event": "json_parse_error", "ok": False, "response_head": content[:200]})
            state["complete"] = True
            return None

        if logger:
            logger({"event": "llm_call_end", "ok": True})

        return result

    except Exception as e:
        if logger:
            logger({"event": "llm_call_exception", "error": repr(e)})
        state["complete"] = True
        return None


    except Exception as e:
        if logger:
            logger({"event": "llm_call_exception", "error": str(e)})
        state["complete"] = True
        return None



# Step 1: Pre-processing
def agent_preprocess(state, logger=None):
    if check_limits(state):
        return state

    messages = [
        {"role": "system", "content": SYS_PREPROCESS},
        {"role": "user", "content": json.dumps({"state": state}, ensure_ascii=False)}
    ]

    msg = call_model(state, messages, logger=logger)
    if msg is None:
        return state

    state["text_preproc"] = msg.get("text_preproc") or msg.get("normalized_text")

    if logger:
        logger({"event": "preprocess_done", "text_preproc": state["text_preproc"]})

    return state


# Step 2: NLACP Identification
def agent_identify(state, logger=None):
    if check_limits(state):
        return state

    messages = [
        {"role": "system", "content": SYS_IDENTIFY},
        {"role": "user", "content": json.dumps({"state": state}, ensure_ascii=False)}
    ]

    msg = call_model(state, messages, logger=logger)
    if msg is None:
        return state

    state["is_nlacp"] = bool(msg.get("is_nlacp"))

    if logger:
        logger({"event": "identify_done", "is_nlacp": state["is_nlacp"]})

    return state


# Step 3: Information Retrieval
def agent_retrieve(state, logger=None):
    if check_limits(state):
        return state

    messages = [
        {"role": "system", "content": SYS_RETRIEVE},
        {"role": "user", "content": json.dumps({
            "state": state,
            "env_data": state.get("env_data", "")
        }, ensure_ascii=False)}
    ]

    msg = call_model(state, messages, logger=logger)
    if msg is None:
        return state

    retr = msg.get("env_var") or {}
    for k in ("subjects", "actions", "resources", "purposes", "conditions"):
        retr.setdefault(k, [])
    state["env_var"] = retr

    if logger:
        logger({
            "event": "retrieve_done",
            "subjects": retr.get("subjects"),
            "actions": retr.get("actions")
        })

    return state


# Step 4 & 4.1: ACP Generation & Post-Processing ( o Step 6 se presente feedback)
def agent_generate(state, logger=None, attack=None):
    if check_limits(state):
        return state

    verifier = state.get("verifier_output") or {}
    has_verified = state.get("has_verified", False) 
    v_status = (verifier.get("status", "") or "").strip().lower()  
    refine_mode = ((has_verified and v_status != "correct") or bool(state.get("feedback")))  


    if refine_mode:
        state["n_iter"] += 1
        if check_limits(state):
            return state

    system_prompt = SYS_REFINE if refine_mode else SYS_GENERATE
    if logger:
        logger({"event": "gen_mode",
                "mode": "refine" if refine_mode else "generate",
                "iteration": state["n_iter"]})

    feedback_val = (state.get("feedback")
                    or (verifier.get("error") if refine_mode else ""))

    user_content = {
        "state": state,
        "env_data": state.get("env_data", ""),
        "feedback": feedback_val
    }

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": json.dumps(user_content, ensure_ascii=False)}
    ]

    msg = call_model(state, messages, logger=logger)
    if msg is None:
        if not refine_mode:
            state["feedback"] = None
        return state

    policy_json = msg.get("policy_json") or state.get("policy_json", {"dsarcp": []})
    if attack:
        policy_json = ensure_sar(
            policy_json,
            state.get("env", "default"),
            vocab=state.get("env_var", {}))
    else:    
        policy_json = ensure_policy_parameters(
            policy_json,
            state.get("env", "default"),
            vocab=state.get("env_var", {})
        )
    state["policy_json"] = policy_json

    if logger:
        preview = state["policy_json"].get("dsarcp", [])[:3]
        logger({"event": "policy_preview", "rules_preview": preview})

    new_fb = msg.get("feedback", None)
    if new_fb is not None:
        state["feedback"] = new_fb
    elif not refine_mode:
        state["feedback"] = None

    if logger:
        logger({
            "event": "refine_done" if refine_mode else "generate_done",
            "iteration": state["n_iter"],
            "rules_count": len(policy_json.get("dsarcp", [])),
            "feedback_used": refine_mode
        })

    return state





# Step 5: Verifica la correttezza della policy generata
def agent_verify(state, logger=None):
    if check_limits(state):
        return state

    messages = [
        {"role": "system", "content": SYS_VERIFY},
        {"role": "user", "content": json.dumps({"state": state}, ensure_ascii=False)}
    ]

    msg = call_model(state, messages, logger=logger)
    if msg is None:
        state["verifier_output"] = {"status": "incorrect", "error": "verify call failed"}
        state["has_verified"] = True
        return state

    report = msg.get("verifier_output") or msg.get("verifier_report") or {}
    status = report.get("status", "incorrect")
    error = report.get("error", "")

    state["verifier_output"] = {"status": status, "error": error}
    state["has_verified"] = True
    state["feedback"] = msg.get("feedback") or state.get("feedback")

    if logger:
        logger({
            "event": "verify_done",
            "status": status,
            "error": error
        })

    return state



