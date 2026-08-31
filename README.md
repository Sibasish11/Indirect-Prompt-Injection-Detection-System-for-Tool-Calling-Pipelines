# Indirect Prompt Injection Detection System

An indirect prompt injection detection system for tool-calling LLM pipelines. SentinelPrompt inspects untrusted content user input, retrieved documents, web pages, or tool/function outputs and classifies whether it contains a prompt injection attack before that content reaches a downstream LLM application.

Live demo: https://ipi333.streamlit.app/

## Why this exists

Agentic LLM applications routinely feed untrusted external content (search results, documents, API responses, tool outputs) back into a model's context. If that content contains hidden instructions, it can hijack the model's behavior this is indirect prompt injection. SentinelPrompt acts as a security scanner that sits in front of that content: it analyzes the content for injection attempts without ever executing any instructions found inside it.

## How it works

1. The application's trusted system instructions, the untrusted external content, and optional conversation context are wrapped in explicit, clearly labeled tags.
2. A fixed system prompt instructs the analysis model that everything inside those tags is data to be examined, never instructions to follow : the same principle as a malware scanner that must not run the malware it is scanning.
3. The model returns a structured JSON verdict: whether an injection was detected, its risk level, confidence, attack type(s), likely attacker intent, supporting evidence, a plain-language reasoning summary, a recommended action, and mitigation steps.
4. 
This isolation pattern (fixed system prompt, tagged untrusted data, structured-output-only response) is the current standard mitigation for indirect prompt injection and does not claim to make injection against the analyzer itself impossible.

## Attack taxonomy

SentinelPrompt classifies content against the following categories:

- **Direct Instruction Override** : content that tells the model to ignore, forget, or override its prior instructions.
- **System Prompt Extraction** : attempts to get the model to reveal or leak its hidden system prompt or configuration.
- **Roleplay Jailbreak** : persona or hypothetical-scenario framing used to bypass normal behavioral constraints.
- **Indirect Prompt Injection** : malicious instructions embedded in external content the model is only supposed to process, not obey.
- **Context Manipulation** : fabricated prior turns, fake system messages, or fake "end of instructions" markers.
- **Instruction Smuggling** : instructions hidden via encoding, unusual formatting, translation, or whitespace tricks.
- **Tool Manipulation** : attempts to make an agent call tools/functions it shouldn't, with unauthorized parameters or sequencing.
- **Data Exfiltration Attempt** : attempts to leak confidential data to an unauthorized party (e.g. via an embedded URL).
- **Privilege Escalation** : content that claims elevated authority (admin, developer, etc.) to unlock restricted behavior.
- **Multi-Turn Manipulation** : an attack spread across multiple turns that builds context or trust exploited later.

Each analysis also returns a risk level (`SAFE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), a confidence score, and a recommended action (`ALLOW`, `FLAG`, `SANITIZE`, `BLOCK`).

<h2>Screenshots Gallery:</h2>
<p>Here’s a quick visual walkthrough of the app:</p>

<h3>Landing Page </h3>
<p align="center">
  <img src="assets/Screenshot 2026-08-24 161418.png" width="900">
</p>

## Project structure

```
.
├── app.py               # Streamlit UI: takes input, runs analysis, renders the verdict
├── core/
│   ├── analyzer.py       # Calls the model via OpenRouter, handles retries and errors
│   ├── prompts.py         # System prompt and untrusted-content isolation/templating
│   ├── taxonomy.py        # Attack type, risk level, and recommended action definitions
│   └── validator.py       # Parses and validates model output into a strict schema
├── data/                 # Notebooks used for exploration/dataset work
├── attacks.json          # Sample test prompts covering the attack taxonomy above
├── requirements.txt
└── .env.example
```

## Getting started

### Prerequisites

- Python 3.10+
- An [OpenRouter](https://openrouter.ai/keys) API key

### Installation

```bash
git clone https://github.com/Sibasish11/Indirect-Prompt-Injection-Detection-System-for-Tool-Calling-Pipelines.git
cd Indirect-Prompt-Injection-Detection-System-for-Tool-Calling-Pipelines
pip install -r requirements.txt
```

### Configuration

Copy the example environment file and add your key:

```bash
cp .env.example .env
```

```env
OPENROUTER_API_KEY=your_openrouter_api_key
OPENROUTER_MODEL=openai/gpt-oss-20b:free
```

`OPENROUTER_MODEL` can be pointed at any chat-completion-capable model available on OpenRouter, including free-tier models.

### Running locally

```bash
streamlit run app.py
```

Enter the (optional) application/system instructions and the content you want to analyze, then click **Analyze** to see the classification, evidence, reasoning, and recommended action.

## Sample test cases

`attacks.json` contains a set of illustrative prompts covering direct overrides, roleplay jailbreaks, indirect injection, instruction smuggling, and multi-turn drift, useful for manually exercising the detector. The labels in this file are rough author assigned expectations for eyeballing results, not a formal benchmark ground truth.
You guys can use them to test the model.
