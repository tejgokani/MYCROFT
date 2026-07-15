# AI_MODE.md — Mycroft Local AI Mode (v1)

Selectable mode. Local LLM assistant that auto-provisions itself and runs as a **visible agent pane**, driving Mycroft's existing scope-guarded, logged runner.

## Flow
1. Operator selects **AI Mode** in the TUI.
2. **Spec probe** — detect RAM, VRAM, GPU vendor, disk free, CPU (cores, AVX).
3. **Gate** — show only models the hardware can run; hard-block the rest with the reason.
4. Operator picks a model.
5. **Provision** — ensure Ollama present (auto-install if missing), then `ollama pull <model>`. Stream setup live into a visible pane (the "builds itself" moment).
6. **Agent loop** — model proposes commands → routed through Scope Guard + Runner → output returned to model. Default: human approves each action.

## Hard rules (inherit CLAUDE.md invariants)
- **Wrap Ollama. Never build model download/serving.** Detect → auto-install → drive via `localhost:11434`.
- **Every AI-issued command passes the Scope Guard and is logged**, identically to human commands (`issued_by = ai`).
- **Propose-then-approve is default.** Autonomous execution ("YOLO mode") is explicit opt-in, with a persistent banner.
- Model output is **untrusted input** — parse defensively; never exec a raw model string without guard + validation.
- Local-only. No cloud model fallback that ships engagement data off-box.

## Spec probe sources
| Signal | Source |
|---|---|
| RAM | `sysinfo` |
| GPU / VRAM | `nvidia-smi` (NVIDIA), `rocminfo` (AMD), Metal (macOS) |
| Disk free | `sysinfo` / statvfs |
| CPU cores / AVX | `sysinfo` / cpuid |

## Model gating (Q4 quantized, approximate — verify at build)
| Model class | Min memory (Q4) | Tier |
|---|---|---|
| 3B (Qwen2.5-3B, Llama-3.2-3B) | ~4 GB | any laptop |
| 7–8B (Llama-3.1-8B, Qwen-7B) | ~6–8 GB | mid |
| 13–14B | ~10–12 GB | good GPU |
| 30–34B | ~20–24 GB | workstation |
| 70B | ~40+ GB | rare |

Block above detected ceiling. Message format: `"<model> needs ~12GB VRAM; detected 6GB — blocked."`

## Agent contract
- **System prompt**: pentest triage/recon assistant with a fixed tool set = Mycroft's runner commands.
- **Tool calls**: model emits a structured action → orchestrator validates → Guard checks → Runner execs → result summarized back.
- **Scope of use**: triage, recon chaining, output summarization, next-step suggestion. **Not** an autonomous exploiter — set this expectation in-UI.

## Sub-agent split for building AI Mode
- **spec-agent** — hardware probe + tier mapping.
- **provision-agent** — Ollama detect/install/pull + visible-pane streaming.
- **orchestrator-agent** — agent loop, tool-call validation, guard routing.
- **aitui-agent** — the AI pane UI + approval prompts.
- **review-agent** — mandatory pass on orchestrator (it's the unit that turns model text into executed commands).

Build these in parallel against the contracts; integrate last.
