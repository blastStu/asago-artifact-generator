"""Self-contained HTML reports for scenarios, artifacts, and generation runs."""

# Embedded CSS/HTML intentionally uses long lines; the generated document is easier to
# audit when its presentation rules remain in one self-contained template.
# ruff: noqa: E501

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

import yaml

from .extract import ScenarioContext, load_scenario
from .garak.spec_io import (
    garak_artifact_path,
    load_garak_artifact,
    validation_path,
)

_LOGO_PATH = Path(__file__).with_name("report_assets") / "asago-main-logo-dark.svg"

_TAXONOMY_GLOSSARY: dict[str, dict[str, str]] = {
    "LLM01": {
        "framework": "OWASP Top 10 for LLM Applications 2025",
        "name": "Prompt Injection",
        "description": "User or external content changes the model's intended behavior or output through malicious instructions.",
        "source": "https://genai.owasp.org/llm-top-10/",
    },
    "LLM02": {
        "framework": "OWASP Top 10 for LLM Applications 2025",
        "name": "Sensitive Information Disclosure",
        "description": "The model or its surrounding application exposes sensitive information through prompts, context, outputs, or connected systems.",
        "source": "https://genai.owasp.org/llm-top-10/",
    },
    "LLM03": {
        "framework": "OWASP Top 10 for LLM Applications 2025",
        "name": "Supply Chain",
        "description": "Third-party models, data, packages, adapters, or deployment components introduce integrity, security, or availability risks.",
        "source": "https://genai.owasp.org/llmrisk/llm032025-supply-chain/",
    },
    "LLM04": {
        "framework": "OWASP Top 10 for LLM Applications 2025",
        "name": "Data and Model Poisoning",
        "description": "Training, fine-tuning, embedding, or other model data is manipulated to introduce bias, backdoors, or unsafe behavior.",
        "source": "https://genai.owasp.org/llm-top-10/",
    },
    "LLM05": {
        "framework": "OWASP Top 10 for LLM Applications 2025",
        "name": "Improper Output Handling",
        "description": "Model output is passed downstream without sufficient validation, sanitization, encoding, or authorization checks.",
        "source": "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
    },
    "LLM06": {
        "framework": "OWASP Top 10 for LLM Applications 2025",
        "name": "Excessive Agency",
        "description": "The model has more functionality, permissions, or autonomy than necessary, allowing manipulated output to trigger damaging actions.",
        "source": "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
    },
    "LLM07": {
        "framework": "OWASP Top 10 for LLM Applications 2025",
        "name": "System Prompt Leakage",
        "description": "System prompts or hidden instructions are disclosed, weakening security controls or revealing sensitive implementation details.",
        "source": "https://genai.owasp.org/llm-top-10/",
    },
    "LLM08": {
        "framework": "OWASP Top 10 for LLM Applications 2025",
        "name": "Vector and Embedding Weaknesses",
        "description": "Weaknesses in vector stores or embeddings allow retrieval manipulation, cross-context exposure, or poisoned context.",
        "source": "https://genai.owasp.org/llm-top-10/",
    },
    "LLM09": {
        "framework": "OWASP Top 10 for LLM Applications 2025",
        "name": "Misinformation",
        "description": "The model produces or amplifies false, misleading, or overconfident information that downstream users or systems rely on.",
        "source": "https://genai.owasp.org/llm-top-10/",
    },
    "LLM10": {
        "framework": "OWASP Top 10 for LLM Applications 2025",
        "name": "Unbounded Consumption",
        "description": "Uncontrolled model usage consumes excessive tokens, compute, money, or other resources and can cause denial of service.",
        "source": "https://genai.owasp.org/llm-top-10/",
    },
    "T1": {
        "framework": "OWASP Agentic AI threat taxonomy",
        "name": "Memory Poisoning",
        "description": "Attacker-controlled content corrupts short- or long-term agent memory so later decisions are influenced by false instructions or facts.",
        "source": "https://agentic-threat-modeling.github.io/MAESTRO/playbook/12-quick-reference.html",
    },
    "T2": {
        "framework": "OWASP Agentic AI threat taxonomy",
        "name": "Tool Misuse",
        "description": "An agent is manipulated into invoking a tool in an unsafe way or for a purpose outside the intended workflow.",
        "source": "https://agentic-threat-modeling.github.io/MAESTRO/playbook/12-quick-reference.html",
    },
    "T3": {
        "framework": "OWASP Agentic AI threat taxonomy",
        "name": "Privilege Compromise",
        "description": "An attacker obtains, abuses, or escalates the permissions available to an agent, tool, or connected identity.",
        "source": "https://agentic-threat-modeling.github.io/MAESTRO/playbook/12-quick-reference.html",
    },
    "T4": {
        "framework": "OWASP Agentic AI threat taxonomy",
        "name": "Resource Overload",
        "description": "Agent behavior exhausts compute, tokens, service capacity, or other resources through excessive or repeated activity.",
        "source": "https://agentic-threat-modeling.github.io/MAESTRO/playbook/12-quick-reference.html",
    },
    "T5": {
        "framework": "OWASP Agentic AI threat taxonomy",
        "name": "Cascading Hallucinations",
        "description": "An incorrect model output is accepted as context by later steps or agents and propagates through the workflow.",
        "source": "https://agentic-threat-modeling.github.io/MAESTRO/playbook/12-quick-reference.html",
    },
    "T6": {
        "framework": "OWASP Agentic AI threat taxonomy",
        "name": "Intent Breaking & Goal Manipulation",
        "description": "The agent's intended objective or constraints are redirected by adversarial instructions, context, or intermediate results.",
        "source": "https://agentic-threat-modeling.github.io/MAESTRO/playbook/12-quick-reference.html",
    },
    "T7": {
        "framework": "OWASP Agentic AI threat taxonomy",
        "name": "Misaligned & Deceptive Behaviour",
        "description": "Agent behavior departs from the user's or system's security objective, including deceptive or strategically misleading actions.",
        "source": "https://agentic-threat-modeling.github.io/MAESTRO/playbook/12-quick-reference.html",
    },
    "T8": {
        "framework": "OWASP Agentic AI threat taxonomy",
        "name": "Repudiation & Untraceability",
        "description": "Missing or unreliable provenance and audit trails make agent decisions or actions difficult to attribute and investigate.",
        "source": "https://agentic-threat-modeling.github.io/MAESTRO/playbook/12-quick-reference.html",
    },
    "T9": {
        "framework": "OWASP Agentic AI threat taxonomy",
        "name": "Identity Spoofing",
        "description": "An attacker impersonates a user, agent, service, or other trusted participant in an agentic workflow.",
        "source": "https://agentic-threat-modeling.github.io/MAESTRO/playbook/12-quick-reference.html",
    },
    "T10": {
        "framework": "OWASP Agentic AI threat taxonomy",
        "name": "Overwhelming HITL",
        "description": "Human reviewers are overloaded with volume, speed, or complexity until meaningful oversight becomes ineffective.",
        "source": "https://agentic-threat-modeling.github.io/MAESTRO/playbook/12-quick-reference.html",
    },
    "T11": {
        "framework": "OWASP Agentic AI threat taxonomy",
        "name": "Unexpected RCE / Code Attacks",
        "description": "Agent-generated or agent-invoked code causes unexpected command execution, code injection, or compromise of the runtime.",
        "source": "https://agentic-threat-modeling.github.io/MAESTRO/playbook/12-quick-reference.html",
    },
    "T12": {
        "framework": "OWASP Agentic AI threat taxonomy",
        "name": "Agent Communication Poisoning",
        "description": "Messages or shared artifacts exchanged between agents are manipulated to influence downstream decisions or actions.",
        "source": "https://agentic-threat-modeling.github.io/MAESTRO/playbook/12-quick-reference.html",
    },
    "T13": {
        "framework": "OWASP Agentic AI threat taxonomy",
        "name": "Rogue Agents",
        "description": "A compromised, malicious, or misbehaving agent acts against the interests of the wider system or its users.",
        "source": "https://agentic-threat-modeling.github.io/MAESTRO/playbook/12-quick-reference.html",
    },
    "T14": {
        "framework": "OWASP Agentic AI threat taxonomy",
        "name": "Human Attacks on MAS",
        "description": "People exploit the coordination, trust, or control relationships in a multi-agent system to cause harmful outcomes.",
        "source": "https://agentic-threat-modeling.github.io/MAESTRO/playbook/12-quick-reference.html",
    },
    "T15": {
        "framework": "OWASP Agentic AI threat taxonomy",
        "name": "Human Trust Manipulation",
        "description": "Agent outputs or behavior manipulate human trust, judgment, or approval decisions.",
        "source": "https://agentic-threat-modeling.github.io/MAESTRO/playbook/12-quick-reference.html",
    },
    "T16": {
        "framework": "OWASP Agentic AI threat taxonomy",
        "name": "Insecure Inter-Agent Protocol Abuse",
        "description": "Weaknesses in agent-to-agent protocols or trust negotiation are exploited to alter messages, identity, or delegated actions.",
        "source": "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/",
    },
    "T17": {
        "framework": "OWASP Agentic AI threat taxonomy",
        "name": "Supply Chain Compromise",
        "description": "An agent, tool, model, package, or other dependency is compromised before or during integration into the system.",
        "source": "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/",
    },
    "AML.T0015": {
        "framework": "MITRE ATLAS",
        "name": "Evade AI Model",
        "description": "Adversarial inputs are crafted to make an AI model misclassify, overlook, or mishandle meaningful content.",
        "source": "https://atlas.mitre.org/techniques/AML.T0015/",
    },
    "AML.T0040": {
        "framework": "MITRE ATLAS",
        "name": "AI Model Inference API Access",
        "description": "The adversary gains legitimate access to a model through its inference API to probe, stage, or influence attacks.",
        "source": "https://atlas.mitre.org/techniques/AML.T0040/",
    },
    "AML.T0048": {
        "framework": "MITRE ATLAS",
        "name": "External Harms",
        "description": "AI-enabled activity causes harm outside the model or application, including financial, reputational, or physical impact.",
        "source": "https://atlas.mitre.org/techniques/AML.T0048/",
    },
    "AML.T0051": {
        "framework": "MITRE ATLAS",
        "name": "LLM Prompt Injection",
        "description": "Crafted prompts cause an LLM to ignore intended instructions and follow adversary-controlled instructions instead.",
        "source": "https://atlas.mitre.org/techniques/AML.T0051/",
    },
    "AML.T0051.000": {
        "framework": "MITRE ATLAS",
        "name": "Direct Prompt Injection",
        "description": "The adversary injects malicious instructions directly into the LLM's input channel.",
        "source": "https://atlas.mitre.org/techniques/AML.T0051.000/",
    },
    "AML.T0051.001": {
        "framework": "MITRE ATLAS",
        "name": "Indirect Prompt Injection",
        "description": "Malicious instructions are hidden in external content, such as a document, website, message, or tool result that the LLM ingests.",
        "source": "https://atlas.mitre.org/techniques/AML.T0051.001/",
    },
    "AML.T0053": {
        "framework": "MITRE ATLAS",
        "name": "AI Agent Tool Invocation",
        "description": "The adversary causes an AI agent to invoke a tool or connected capability in an unintended or harmful way.",
        "source": "https://atlas.mitre.org/techniques/AML.T0053/",
    },
    "AML.T0067": {
        "framework": "MITRE ATLAS",
        "name": "LLM Trusted Output Components Manipulation",
        "description": "The response is shaped to look trustworthy by manipulating links, citations, metadata, follow-up actions, or other trust signals.",
        "source": "https://atlas.mitre.org/techniques/AML.T0067/",
    },
}


def _escape(value: Any) -> str:
    return html.escape(str(value if value not in (None, "") else "—"), quote=True)


def _json(value: Any) -> str:
    return html.escape(json.dumps(value, indent=2, ensure_ascii=False), quote=False)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _load_manifest(runs_dir: Path) -> dict[str, dict[str, Any]]:
    data = _read_json(runs_dir / "manifest.json")
    if not isinstance(data, list):
        return {}
    return {
        str(entry.get("scenario_id")): entry
        for entry in data
        if isinstance(entry, dict) and entry.get("scenario_id")
    }


def _load_run_log(runs_dir: Path, requested: Path | None) -> dict[str, Any] | None:
    if requested is not None:
        data = _read_json(requested)
        return data if isinstance(data, dict) else None
    directory = runs_dir / "generation-log"
    paths = sorted(directory.glob("*.json")) if directory.is_dir() else []
    if not paths:
        return None
    data = _read_json(paths[-1])
    return data if isinstance(data, dict) else None


def _artifact_path(
    scenario_id: str,
    manifest_entry: dict[str, Any],
    runs_dir: Path,
) -> Path | None:
    candidates: list[Path] = []
    recorded = manifest_entry.get("artifact_path")
    if isinstance(recorded, str) and recorded:
        candidates.extend((Path(recorded), runs_dir / recorded))
    candidates.append(garak_artifact_path(scenario_id, runs_dir))
    return next((path for path in candidates if path.is_file()), None)


def _scenario_contexts(scenarios_dir: Path) -> dict[str, ScenarioContext]:
    contexts: dict[str, ScenarioContext] = {}
    for path in sorted(scenarios_dir.glob("AP-*.yaml")):
        try:
            context = load_scenario(path)
        except (OSError, ValueError, yaml.YAMLError):
            continue
        contexts[context.scenario_id] = context
    return contexts


def _report_views(
    scenarios_dir: Path,
    runs_dir: Path,
    run_log: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    contexts = _scenario_contexts(scenarios_dir)
    manifest = _load_manifest(runs_dir)
    logged = {
        str(entry.get("scenario_id")): entry
        for entry in (run_log or {}).get("scenarios", [])
        if isinstance(entry, dict) and entry.get("scenario_id")
    }
    # A generation log is the authoritative scope for a report. The input
    # directory can contain many scenarios that were not part of this run.
    # Fall back to the manifest for runs created before generation logs were
    # added, and only use all input scenarios when no run metadata exists.
    if run_log is not None and "scenarios" in run_log:
        scenario_ids = set(logged)
    elif manifest:
        scenario_ids = set(manifest)
    else:
        scenario_ids = set(contexts)
    views: list[dict[str, Any]] = []

    for scenario_id in sorted(scenario_ids):
        manifest_entry = manifest.get(scenario_id, {})
        log_entry = logged.get(scenario_id, {})
        artifact_file = _artifact_path(scenario_id, manifest_entry, runs_dir)
        artifact: dict[str, Any] | None = None
        artifact_error = ""
        if artifact_file:
            try:
                artifact = load_garak_artifact(artifact_file)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                artifact_error = str(exc)

        validation_file = validation_path(scenario_id, runs_dir)
        validation = _read_json(validation_file) if validation_file.is_file() else None
        validation_errors = validation.get("errors", []) if isinstance(validation, dict) else []
        if not isinstance(validation_errors, list):
            validation_errors = [str(validation_errors)]

        context = contexts.get(scenario_id)
        status = "not_generated"
        if manifest_entry.get("gate_result") == "skip":
            status = "skipped"
        elif manifest_entry:
            status = "success" if manifest_entry.get("ok") else "failed"
        elif artifact:
            status = "success" if validation is None or validation.get("ok", True) else "failed"
        if validation is not None and not validation.get("ok", True):
            status = "failed"
        if log_entry.get("status") == "error":
            status = "error"

        raw = context.raw if context else {}
        narrative = raw.get("narrative") or {}
        metadata = raw.get("scenario_seed_metadata") or {}
        actor = raw.get("actor_profile") or {}
        tree = raw.get("attack_tree") or {}
        risk = (raw.get("faceting") or {}).get("risk_card") or {}
        views.append(
            {
                "scenario_id": scenario_id,
                "status": status,
                "context": context,
                "artifact": artifact,
                "artifact_file": str(artifact_file) if artifact_file else "",
                "artifact_error": artifact_error,
                "validation": validation or {},
                "validation_errors": validation_errors,
                "manifest": manifest_entry,
                "log": log_entry,
                "title": narrative.get("title", ""),
                "summary": narrative.get("summary", ""),
                "entry_point": narrative.get("entry_point", ""),
                "zone_sequence": narrative.get("zone_sequence") or [],
                "steps": narrative.get("steps") or [],
                "threat_name": metadata.get("threat_name", ""),
                "mechanism_name": metadata.get("mechanism_name", ""),
                "mechanism_description": metadata.get("mechanism_description", ""),
                "actor_type": actor.get("actor_type", ""),
                "capability_level": actor.get("capability_level", ""),
                "beliefs": actor.get("beliefs") or [],
                "attack_goal": tree.get("goal", ""),
                "tags": ((raw.get("faceting") or {}).get("taxonomy_chain") or {}),
                "risk": risk,
            }
        )
    return views


def _explanation(text: str) -> str:
    return f'<div class="explanation"><strong>What this means:</strong> {_escape(text)}</div>'


def _badge(label: Any, kind: str = "neutral") -> str:
    return f'<span class="badge {kind}">{_escape(label)}</span>'


def _status_badge(status: str) -> str:
    kind = {
        "success": "success",
        "skipped": "skip",
        "failed": "failure",
        "error": "failure",
    }.get(status, "neutral")
    return _badge(status.replace("_", " "), kind)


def _render_tags(taxonomy: dict[str, Any]) -> str:
    tags: list[str] = []
    for values in taxonomy.values():
        if isinstance(values, list):
            tags.extend(str(value) for value in values)
    buttons = []
    for tag in dict.fromkeys(tags):
        entry = _TAXONOMY_GLOSSARY.get(tag, {})
        label = entry.get("name", "Open taxonomy details")
        buttons.append(
            f'<button type="button" class="taxonomy-tag" '
            f'data-taxonomy-id="{_escape(tag)}" title="{_escape(label)}">{_escape(tag)}</button>'
        )
    return " ".join(buttons) or "<span>—</span>"


def _render_steps(steps: list[dict[str, Any]]) -> str:
    if not steps:
        return "<p>No narrative steps were recorded.</p>"
    cards = []
    for step in steps:
        cards.append(
            '<article class="step">'
            f'<div class="step-heading"><strong>Step {_escape(step.get("step_number"))}</strong> '
            f"{_badge(step.get('zone', ''))}</div>"
            f"<p><strong>Action:</strong> {_escape(step.get('action'))}</p>"
            f"<p><strong>Effect:</strong> {_escape(step.get('effect'))}</p>"
            f"<p><strong>Control point:</strong> {_escape(step.get('control_point'))}</p>"
            "</article>"
        )
    return "".join(cards)


def _render_turns(artifact: dict[str, Any]) -> str:
    turns = artifact.get("turns") or []
    attack_index = artifact.get("attack_turn_index")
    if not turns:
        return "<p>No transcript was written for this scenario.</p>"
    rendered: list[str] = []
    for index, turn in enumerate(turns):
        role = str(turn.get("role", "unknown"))
        classes = f"turn role-{html.escape(role)}"
        if index == attack_index or turn.get("adversarial"):
            classes += " adversarial"
        calls = turn.get("tool_calls") or []
        call_html = f"<pre>{_json(calls)}</pre>" if calls else ""
        tool_calls_html = (
            f'<div class="tool-calls"><strong>Tool calls</strong>{call_html}</div>'
            if call_html
            else ""
        )
        adversarial_badge = (
            _badge("adversarial", "danger")
            if index == attack_index or turn.get("adversarial")
            else ""
        )
        tool_meta = ""
        if role == "tool":
            tool_meta = (
                f'<div class="turn-meta">tool: {_escape(turn.get("name") or turn.get("tool_name"))} '
                f"· call: {_escape(turn.get('tool_call_id'))}</div>"
            )
        rendered.append(
            f'<article class="{classes}"><div class="turn-heading">'
            f"<strong>Turn {index}</strong> {_badge(role)} "
            f"{adversarial_badge}</div>{tool_meta}"
            f'<div class="turn-content">{_escape(turn.get("content", ""))}</div>'
            f"{tool_calls_html}"
            "</article>"
        )
    return "".join(rendered)


def _render_rubric(artifact: dict[str, Any]) -> str:
    rubric = artifact.get("detector_rubric") or {}
    rubrics = rubric.get("rubrics") or {}
    success = "".join(f"<li>{_escape(item)}</li>" for item in rubrics.get("attack_success", []))
    blocked = "".join(f"<li>{_escape(item)}</li>" for item in rubrics.get("attack_blocked", []))
    return (
        f"<p><strong>Judge prompt:</strong> {_escape(rubric.get('judge_prompt'))}</p>"
        f"<p><strong>Ground-truth context:</strong> {_escape(rubric.get('context'))}</p>"
        '<div class="rubric-grid"><div><h4>Attack succeeds when…</h4>'
        f"<ul>{success or '<li>None recorded.</li>'}</ul></div>"
        "<div><h4>Attack is blocked when…</h4>"
        f"<ul>{blocked or '<li>None recorded.</li>'}</ul></div></div>"
    )


def _render_input(view: dict[str, Any]) -> str:
    return (
        _explanation(
            "This is the threat-model input. It describes the situation the generated "
            "artifact is intended to test; it is not itself the model response."
        )
        + f'<dl class="facts"><dt>Threat</dt><dd>{_escape(view["threat_name"])}</dd>'
        f"<dt>Mechanism</dt><dd>{_escape(view['mechanism_name'])}</dd>"
        f"<dt>Entry point</dt><dd>{_escape(view['entry_point'])}</dd>"
        f"<dt>Zone sequence</dt><dd>{' → '.join(_escape(z) for z in view['zone_sequence']) or '—'}</dd>"
        f"<dt>Actor</dt><dd>{_escape(view['actor_type'])} / {_escape(view['capability_level'])}</dd>"
        f"<dt>Attack goal</dt><dd>{_escape(view['attack_goal'])}</dd></dl>"
        f"<h4>Scenario summary</h4><p>{_escape(view['summary'])}</p>"
        "<h4>Narrative steps</h4>"
        f'<div class="steps">{_render_steps(view["steps"])}</div>'
        "<h4>Taxonomy tags</h4>"
        + _explanation(
            "These tags map the scenario to external threat and risk taxonomies. "
            "Select a tag to open its name, meaning, and reference link."
        )
        + f'<div class="tags">{_render_tags(view["tags"])}</div>'
    )


def _render_artifact(view: dict[str, Any]) -> str:
    artifact = view.get("artifact")
    if not artifact:
        return (
            _explanation(
                "No usable artifact is available. This usually means generation failed "
                "validation or the scenario was not run."
            )
            + f"<p>{_escape(view.get('artifact_error') or 'No artifact file recorded.')}</p>"
        )
    return (
        _explanation(
            "This is the Garak input produced for the target system. Garak replays the "
            "transcript and judges the target's next response against the detector rubric."
        )
        + f'<dl class="facts"><dt>Artifact model</dt><dd>{_escape(artifact.get("model"))}</dd>'
        f"<dt>Injection surface</dt><dd>{_escape(artifact.get('injection_surface'))}</dd>"
        f"<dt>Garak coverage</dt><dd>{_escape(artifact.get('platform_coverage'))}</dd>"
        f"<dt>Attack turn</dt><dd>{_escape(artifact.get('attack_turn_index'))}</dd>"
        f"<dt>Generated at</dt><dd>{_escape(artifact.get('timestamp'))}</dd></dl>"
        "<h4>Transcript</h4>"
        + _explanation(
            "System and user turns establish context. Assistant/tool turns are fixed "
            "context for Garak. The highlighted adversarial turn is the injected input "
            "whose effect is measured by the detector."
        )
        + f'<div class="transcript">{_render_turns(artifact)}</div>'
        "<h4>Detector rubric</h4>"
        + _explanation(
            "The judge sees the target's next message and uses these observable "
            "success and blocked predicates to decide whether the attack worked."
        )
        + _render_rubric(artifact)
    )


def _render_generation(view: dict[str, Any]) -> str:
    entry = view.get("log") or {}
    failures = entry.get("attempt_failures") or []
    failure_html = "".join(f"<li><pre>{_json(item)}</pre></li>" for item in failures)
    errors = view.get("validation_errors") or []
    error_html = "".join(f"<li>{_escape(item)}</li>" for item in errors)
    return (
        _explanation(
            "These settings and events were captured during generation. They describe "
            "what actually ran, rather than re-reading the current .env file. API keys "
            "and full prompts are intentionally excluded."
        )
        + f'<dl class="facts"><dt>Status</dt><dd>{_status_badge(view["status"])}</dd>'
        f"<dt>Attempts</dt><dd>{_escape(entry.get('attempts', '—'))}</dd>"
        f"<dt>Duration</dt><dd>{_escape(entry.get('duration_seconds', '—'))} seconds</dd>"
        f"<dt>Source</dt><dd><code>{_escape(entry.get('source_path') or '—')}</code></dd>"
        f"<dt>Artifact path</dt><dd><code>{_escape(view.get('artifact_file') or '—')}</code></dd></dl>"
        f"<h4>Attempt failures</h4><ul>{failure_html or '<li>None recorded.</li>'}</ul>"
        f"<h4>Validation errors</h4><ul>{error_html or '<li>None recorded.</li>'}</ul>"
    )


def _render_raw(view: dict[str, Any]) -> str:
    context = view.get("context")
    raw = dict(context.raw) if context else {}
    raw.pop("_feature_text", None)
    return (
        _explanation(
            "These are the underlying files for readers who need to audit the rendered "
            "summary. The report presentation above is derived from this data."
        )
        + f"<details><summary>Input scenario YAML</summary><pre>{_escape(yaml.safe_dump(raw, sort_keys=False))}</pre></details>"
        + (
            f"<details><summary>Generated artifact JSON</summary><pre>{_json(view['artifact'])}</pre></details>"
            if view.get("artifact")
            else ""
        )
    )


def _render_scenario(view: dict[str, Any]) -> str:
    status = _status_badge(view["status"])
    coverage = view["manifest"].get("gate_result") or (view["artifact"] or {}).get(
        "platform_coverage"
    )
    search_text = " ".join(
        str(view.get(key, ""))
        for key in ("scenario_id", "title", "summary", "threat_name", "mechanism_name")
    )
    return (
        f'<details class="scenario-card" data-search="{_escape(search_text)}">'
        f'<summary><span class="scenario-title"><strong>{_escape(view["scenario_id"])}</strong> '
        f'{_escape(view["title"])}</span><span class="summary-badges">'
        f"{status} {_badge(coverage or 'no coverage', 'coverage')}</span></summary>"
        '<div class="scenario-body">'
        f'<p class="summary">{_escape(view["summary"])}</p>'
        "<section><h3>Input scenario</h3>"
        f"{_render_input(view)}</section>"
        "<section><h3>Generated artifact</h3>"
        f"{_render_artifact(view)}</section>"
        "<section><h3>Generation log</h3>"
        f"{_render_generation(view)}</section>"
        "<section><h3>Raw details</h3>"
        f"{_render_raw(view)}</section>"
        "</div></details>"
    )


def _logo() -> str:
    try:
        return _LOGO_PATH.read_text(encoding="utf-8")
    except OSError:
        return '<div class="wordmark">asago</div>'


def _settings_table(settings: dict[str, Any]) -> str:
    rows = []
    for key, value in settings.items():
        if isinstance(value, list):
            value = "; ".join(str(item) for item in value)
        rows.append(f"<tr><th>{_escape(key)}</th><td>{_escape(value)}</td></tr>")
    return "<table><tbody>" + "".join(rows) + "</tbody></table>"


def _taxonomy_drawer() -> str:
    return (
        '<div id="taxonomy-backdrop" class="taxonomy-backdrop"></div>'
        '<aside id="taxonomy-drawer" class="taxonomy-drawer" aria-hidden="true" '
        'aria-labelledby="taxonomy-drawer-title">'
        '<div class="taxonomy-drawer-header"><div><p class="eyebrow">Taxonomy reference</p>'
        '<h2 id="taxonomy-drawer-title">Select a tag</h2></div>'
        '<button type="button" id="taxonomy-close" class="taxonomy-close" aria-label="Close taxonomy details">×</button></div>'
        '<div id="taxonomy-detail" class="taxonomy-detail">'
        "<p>Click a taxonomy tag in a scenario to see what the identifier means.</p>"
        "</div></aside>"
    )


def render_report(
    *,
    scenarios_dir: Path = Path("examples/scenarios"),
    runs_dir: Path = Path("runs"),
    run_log_path: Path | None = None,
) -> str:
    """Render a self-contained HTML report from repository run data."""
    run_log = _load_run_log(runs_dir, run_log_path)
    views = _report_views(scenarios_dir, runs_dir, run_log)
    status_counts = {
        status: sum(view["status"] == status for view in views)
        for status in ("success", "failed", "error", "skipped", "not_generated")
    }
    coverage_counts = {
        coverage: sum(
            (
                view["manifest"].get("gate_result")
                or (view["artifact"] or {}).get("platform_coverage")
            )
            == coverage
            for view in views
        )
        for coverage in ("full", "partial", "skip")
    }
    settings = (run_log or {}).get("settings") or {}
    run_label = (run_log or {}).get("run_id") or "No persisted generation log found"
    scenario_html = "".join(_render_scenario(view) for view in views)
    taxonomy_data = json.dumps(_TAXONOMY_GLOSSARY, ensure_ascii=False).replace("<", "\\u003c")
    css = """
      :root { --navy:#10243e; --blue:#4b85ff; --teal:#00cec6; --ink:#172033;
        --muted:#667085; --line:#dce3ee; --panel:#fff; --bg:#f5f8fc; }
      * { box-sizing:border-box; } body { margin:0; color:var(--ink); background:var(--bg);
        font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
      .hero { color:white; background:linear-gradient(120deg,var(--navy),#17365e); padding:30px max(24px,calc((100% - 1320px)/2)); }
      .brand { display:flex; align-items:center; gap:20px; } .brand svg { width:130px; height:52px; object-fit:contain; }
      .wordmark { color:white; font-size:28px; font-weight:800; letter-spacing:-1px; }
      h1,h2,h3,h4 { line-height:1.2; } h1 { margin:16px 0 4px; font-size:32px; } h2 { margin-top:32px; }
      .hero p { color:#d9e6f7; margin:6px 0 0; } main { max-width:1320px; margin:0 auto; padding:24px; }
      .dashboard { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:14px; }
      .metric,.panel,.scenario-card { background:var(--panel); border:1px solid var(--line); border-radius:12px; box-shadow:0 3px 12px #10243e0d; }
      .metric { padding:18px; } .metric strong { display:block; font-size:28px; color:var(--navy); } .metric span { color:var(--muted); }
      .panel { padding:20px; margin-top:18px; } .explanation { background:#edf6ff; border-left:4px solid var(--blue); color:#344054; padding:11px 14px; margin:12px 0 18px; }
      .explanation strong { color:var(--navy); } table { border-collapse:collapse; width:100%; } th,td { text-align:left; border-bottom:1px solid var(--line); padding:8px; vertical-align:top; }
      th { color:var(--muted); width:240px; font-weight:600; } code,pre { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
      pre { white-space:pre-wrap; overflow:auto; background:#f7f9fc; border:1px solid var(--line); border-radius:8px; padding:12px; }
      .toolbar { display:flex; gap:12px; margin:18px 0; } input { flex:1; border:1px solid var(--line); border-radius:8px; padding:11px 12px; font:inherit; }
      .scenario-card { margin:12px 0; overflow:hidden; } .scenario-card[hidden] { display:none; }
      .scenario-card > summary { cursor:pointer; list-style:none; display:flex; justify-content:space-between; gap:16px; padding:17px 20px; }
      .scenario-card > summary::-webkit-details-marker { display:none; } .scenario-title { min-width:0; } .summary-badges { white-space:nowrap; }
      .scenario-body { border-top:1px solid var(--line); padding:0 20px 22px; } .scenario-body section { border-top:1px solid var(--line); margin-top:24px; padding-top:8px; }
      .badge { display:inline-block; border-radius:999px; background:#eef2f7; color:#475467; padding:2px 9px; margin:2px 3px 2px 0; font-size:12px; font-weight:650; text-transform:capitalize; }
      .badge.success { background:#dcfae6; color:#067647; } .badge.failure,.badge.danger { background:#fee4e2; color:#b42318; }
      .badge.skip { background:#fff1c2; color:#8b5e00; } .badge.coverage { background:#e6f0ff; color:#2455b8; }
      .taxonomy-tag { border:1px solid #b8c8e1; border-radius:999px; background:#f4f7fc; color:#2455b8; cursor:pointer; padding:3px 10px; margin:2px 3px 2px 0; font:650 12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace; }
      .taxonomy-tag:hover,.taxonomy-tag:focus-visible { background:#e6f0ff; border-color:#4b85ff; outline:2px solid #b8d0ff; outline-offset:1px; }
      .taxonomy-backdrop { display:none; position:fixed; inset:0; z-index:20; background:#10243e66; }
      .taxonomy-backdrop.open { display:block; }
      .taxonomy-drawer { position:fixed; z-index:30; top:0; right:0; width:min(460px,92vw); height:100vh; overflow:auto; padding:24px; background:#fff; box-shadow:-8px 0 30px #10243e33; transform:translateX(105%); transition:transform .2s ease; }
      .taxonomy-drawer.open { transform:translateX(0); }
      .taxonomy-drawer-header { display:flex; justify-content:space-between; gap:18px; align-items:flex-start; border-bottom:1px solid var(--line); padding-bottom:16px; }
      .taxonomy-drawer h2 { margin:0; font-size:24px; } .eyebrow { margin:0 0 5px; color:var(--blue); font-size:12px; font-weight:750; letter-spacing:.08em; text-transform:uppercase; }
      .taxonomy-close { border:0; background:transparent; color:var(--muted); cursor:pointer; font-size:30px; line-height:1; padding:0 4px; }
      .taxonomy-close:hover,.taxonomy-close:focus-visible { color:var(--navy); outline:2px solid #b8d0ff; border-radius:5px; }
      .taxonomy-detail { padding-top:20px; } .taxonomy-detail h3 { margin:0 0 8px; color:var(--navy); font-size:21px; }
      .taxonomy-detail .taxonomy-code { color:var(--blue); font:700 13px ui-monospace,SFMono-Regular,Menlo,monospace; }
      .taxonomy-detail .taxonomy-framework { color:var(--muted); font-weight:650; }
      .taxonomy-detail .taxonomy-description { margin:18px 0; } .taxonomy-detail a { color:#2455b8; font-weight:650; }
      .facts { display:grid; grid-template-columns:minmax(130px,220px) 1fr; margin:0; } .facts dt,.facts dd { border-bottom:1px solid var(--line); padding:8px 0; }
      .facts dt { color:var(--muted); font-weight:650; } .facts dd { margin:0; } .steps { display:grid; gap:10px; }
      .step { border:1px solid var(--line); border-radius:9px; padding:12px 14px; } .step p { margin:8px 0 0; } .step-heading { display:flex; gap:6px; align-items:center; }
      .tags { line-height:2.3; } .transcript { display:grid; gap:10px; } .turn { border:1px solid var(--line); border-left:5px solid #98a2b3; border-radius:8px; padding:12px; }
      .turn.role-system { border-left-color:#7f56d9; } .turn.role-user { border-left-color:#4b85ff; } .turn.role-assistant { border-left-color:#00a99d; }
      .turn.role-tool { border-left-color:#f79009; } .turn.adversarial { background:#fff8ed; border-color:#fdb022; }
      .turn-heading { display:flex; align-items:center; gap:5px; margin-bottom:7px; } .turn-content { white-space:pre-wrap; }
      .turn-meta { color:var(--muted); font-size:12px; margin-bottom:7px; } .tool-calls { margin-top:10px; }
      .rubric-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:16px; } .rubric-grid > div { background:#f7f9fc; border-radius:8px; padding:4px 14px; }
      details summary { cursor:pointer; } .raw details { margin:10px 0; } footer { color:var(--muted); padding:30px 0 10px; font-size:13px; }
      @media (max-width:700px) { .scenario-card > summary { display:block; } .summary-badges { display:block; margin-top:8px; } .facts { grid-template-columns:1fr; } th { width:auto; } }
    """
    javascript = """
      const filter = document.querySelector('#scenario-filter');
      const cards = [...document.querySelectorAll('.scenario-card')];
      filter?.addEventListener('input', () => {
        const needle = filter.value.trim().toLowerCase();
        cards.forEach(card => { card.hidden = needle && !card.dataset.search.toLowerCase().includes(needle); });
      });
      const taxonomy = JSON.parse(document.querySelector('#taxonomy-data').textContent);
      const drawer = document.querySelector('#taxonomy-drawer');
      const backdrop = document.querySelector('#taxonomy-backdrop');
      const closeButton = document.querySelector('#taxonomy-close');
      const detail = document.querySelector('#taxonomy-detail');
      const closeTaxonomy = () => {
        drawer.classList.remove('open');
        backdrop.classList.remove('open');
        drawer.setAttribute('aria-hidden', 'true');
      };
      const openTaxonomy = id => {
        const item = taxonomy[id] || {
          framework: 'Unmapped taxonomy identifier',
          name: 'No bundled description',
          description: 'This identifier is present in the scenario metadata, but this report does not yet include a glossary entry for it.',
          source: ''
        };
        document.querySelector('#taxonomy-drawer-title').textContent = item.name;
        detail.replaceChildren();
        const code = document.createElement('p');
        code.className = 'taxonomy-code';
        code.textContent = id;
        const framework = document.createElement('p');
        framework.className = 'taxonomy-framework';
        framework.textContent = item.framework;
        const description = document.createElement('p');
        description.className = 'taxonomy-description';
        description.textContent = item.description;
        detail.append(code, framework, description);
        if (item.source) {
          const source = document.createElement('a');
          source.href = item.source;
          source.target = '_blank';
          source.rel = 'noopener noreferrer';
          source.textContent = 'Open reference source';
          detail.append(source);
        }
        drawer.classList.add('open');
        backdrop.classList.add('open');
        drawer.setAttribute('aria-hidden', 'false');
        closeButton.focus();
      };
      document.querySelectorAll('.taxonomy-tag').forEach(tag => {
        tag.addEventListener('click', () => openTaxonomy(tag.dataset.taxonomyId));
      });
      closeButton.addEventListener('click', closeTaxonomy);
      backdrop.addEventListener('click', closeTaxonomy);
      document.addEventListener('keydown', event => { if (event.key === 'Escape') closeTaxonomy(); });
    """
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>Asago Artifact Report</title><style>"
        + css
        + "</style></head><body>"
        + f'<header class="hero"><div class="brand">{_logo()}</div>'
        + "<h1>Artifact generation report</h1>"
        + "<p>A readable view of threat scenarios, generated Garak artifacts, and the run that produced them.</p></header>"
        + "<main>"
        + '<section class="panel"><h2>How to read this report</h2>'
        + _explanation(
            "Start with the status cards and scenario list. Open a scenario to move from "
            "the human-readable threat description to the generated transcript, then to "
            "the detector rubric and generation diagnostics."
        )
        + f'<div class="dashboard"><div class="metric"><strong>{len(views)}</strong><span>scenarios shown</span></div>'
        + f'<div class="metric"><strong>{status_counts["success"]}</strong><span>valid artifacts</span></div>'
        + f'<div class="metric"><strong>{status_counts["failed"] + status_counts["error"]}</strong><span>failures</span></div>'
        + f'<div class="metric"><strong>{status_counts["skipped"]}</strong><span>skipped</span></div>'
        + f'<div class="metric"><strong>{coverage_counts["full"]}</strong><span>full coverage</span></div>'
        + f'<div class="metric"><strong>{coverage_counts["partial"]}</strong><span>partial coverage</span></div></div></section>'
        + '<section class="panel"><h2>Generation run</h2>'
        + _explanation(
            "This is the configuration snapshot and run-level log. It is captured when "
            "generation starts, so it remains useful after .env changes. Secrets and full "
            "prompts are never included."
        )
        + f"<p><strong>Run ID:</strong> <code>{_escape(run_label)}</code></p>"
        + (
            _settings_table(settings)
            if settings
            else "<p>No generation log was found for this report.</p>"
        )
        + "</section>"
        + '<section class="panel"><h2>Scenarios in this run</h2>'
        + _explanation(
            "A scenario is the input threat model. Coverage describes how much of that "
            "threat Garak can express; validation describes whether the generated artifact "
            "has the required structure. These are separate concepts."
        )
        + '<div class="toolbar"><input id="scenario-filter" type="search" placeholder="Filter by ID, title, threat, or mechanism…"></div>'
        + (scenario_html or "<p>No scenarios or artifacts were found.</p>")
        + "</section><footer>Generated by Asago Artifact Generator. AI-generated content is disclosed in each artifact.</footer>"
        + "</main>"
        + _taxonomy_drawer()
        + f'<script type="application/json" id="taxonomy-data">{taxonomy_data}</script><script>'
        + javascript
        + "</script></body></html>"
    )
