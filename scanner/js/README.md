# TrustShell static engine — TS/JS analyzer

The Python engine ([`../static_scan.py`](../static_scan.py)) parses **Python** agents with the
`ast` module. This is its counterpart for **TypeScript / JavaScript** agents: it walks a real AST
via the TypeScript compiler API (handles `.ts/.tsx/.js/.jsx/.mjs/.cjs`, no tsconfig needed) and
flags candidate vulnerable paths mapped to the RT-1…RT-9 classes — the same AST-quality triage
Python targets get, instead of coarse line-regex.

It **parses** the source, never executes it (safe on untrusted agent code).

## Install

```bash
cd scanner/js
npm install        # pulls the `typescript` parser
```

## Use

Usually you don't call it directly — `static_scan.py` auto-detects Node and shells to it for TS/JS
files, falling back to line-regex when Node or `typescript` is absent (so the Python core stays
zero-dependency):

```bash
python3 scanner/static_scan.py --source /path/to/ts-agent      # uses this analyzer if available
```

Standalone / JSON:

```bash
node scanner/js/analyze.mjs --source /path/to/ts-agent --json
```

Output shape matches the Python engine: `{ engine, source, count, candidates:[{rt,severity,file,line,why,snippet}] }`.

## What it flags (syntactic candidates)

| RT | Signal |
|---|---|
| RT-3 | `child_process.exec/execSync/spawn…`, `eval(...)`, `new Function(...)` |
| RT-6 | `fs.writeFile/appendFile…` into a memory file (`USER.md`, `/memories/`), or a `memory/persist/curate` function that writes |
| RT-7 | dynamic `require(x)` / `import(x)` with a non-literal specifier |
| RT-8 | `console.*` logging `apiKey/token/secret/process.env` |
| RT-1 | a `prompt/system/instruction` function concatenating untrusted content (`message/body/content/ticket…`) |
| RT-GUARD | a `filter/sanitize/scan/guard` function that blocks by regex/keyword only |

Candidate ≠ vulnerability — confirm dynamically with the [attacker](../../attacker/). License: MIT.
