#!/usr/bin/env node
/**
 * TrustShell static engine v0 — TS/JS analyzer.
 *
 * The Python engine (static.py) parses Python targets with the ast module; this is its counterpart
 * for TypeScript / JavaScript agents. It walks a real AST via the TypeScript compiler API (handles
 * .ts/.tsx/.js/.jsx/.mjs/.cjs uniformly, no tsconfig needed) and flags CANDIDATE vulnerable paths
 * mapped to the RT-1..RT-9 attack classes — triage, not a verdict.
 *
 * Usage:  node analyze.mjs --source /path/to/agent [--json]
 * Output: JSON { engine, source, count, candidates:[{rt,severity,file,line,why,snippet}] }
 *
 * Read-only: it PARSES the source, never executes it. Requires the `typescript` package
 * (npm install). If it's missing, static.py falls back to coarse line-regex, so the Python core
 * stays zero-dependency.
 */
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

let ts;
try {
  ts = (await import("typescript")).default;
} catch {
  process.stderr.write("typescript package not found (run: npm install in scanner/js)\n");
  process.exit(3);
}

// ── hint sets (mirror static.py) ──────────────────────────────────────────
const EXEC_METHODS = new Set(["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"]);
const MEMORY_HINTS = ["memory", "memories", "user.md", "profile", "remember", "curate", "persist"];
const SECRET_HINTS = ["api_key", "apikey", "apiKey", "secret", "token", "password", "passwd", "process.env", "credential", "bearer"];
const UNTRUSTED_HINTS = ["message", "ticket", "content", "page", "html", "email", "body", "payload",
  "toolresult", "tool_result", "observation", "fetch", "crawl", "scrape", "req.body", "request"];
const WRITE_METHODS = new Set(["writeFile", "writeFileSync", "appendFile", "appendFileSync"]);
const GUARD_NAME = ["filter", "sanitiz", "scan", "guard", "block", "threat", "detect"];
const MEMORY_FN = ["memory", "remember", "curate", "persist", "profile"];
const PROMPT_FN = ["prompt", "system", "instruction"];

// Process-spawning APIs that are unambiguous by name (not resolved via imports)
const KNOWN_PROC_CALLS = new Set(["Bun.spawn", "Bun.spawnSync", "Deno.Command", "Deno.run"]);
const CHILD_PROCESS_MODULES = new Set(["child_process", "node:child_process"]);

const SRC_EXT = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];
const SKIP = ["/.git", "/node_modules", "/venv", "/.venv", "/__pycache__", "/dist", "/build", "/.next"];

function walk(root, acc = [], budget = { n: 6000 }) {
  let entries;
  try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch { return acc; }
  for (const e of entries) {
    const full = path.join(root, e.name);
    if (e.isDirectory()) {
      if (SKIP.some((s) => ("/" + full).includes(s))) continue;
      walk(full, acc, budget);
    } else if (SRC_EXT.includes(path.extname(e.name))) {
      acc.push(full);
      if (--budget.n <= 0) return acc;
    }
  }
  return acc;
}

// dotted callee name, e.g. child_process.exec → "child_process.exec"
function calleeName(expr) {
  if (!expr) return "";
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr)) return calleeName(expr.expression) + "." + expr.name.text;
  return "";
}
const lastSeg = (dotted) => dotted.split(".").pop() || "";

function lower(s) { return (s || "").toLowerCase(); }
function anyHint(text, hints) { const t = lower(text); return hints.some((h) => t.includes(lower(h))); }

/**
 * Collect local identifiers actually bound to child_process, so we only flag real command
 * execution. Without this, JS regex `.exec()` and Effect/session `.fork()` flood RT-3 with
 * false positives — measured on a real 3k-file agent codebase.
 */
function collectProcessBindings(sf) {
  const names = new Set();
  const visit = (node) => {
    // import cp from "child_process" / * as cp / { exec, spawn as sp }
    if (ts.isImportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)
        && CHILD_PROCESS_MODULES.has(node.moduleSpecifier.text)) {
      const c = node.importClause;
      if (c) {
        if (c.name) names.add(c.name.text);
        if (c.namedBindings) {
          if (ts.isNamespaceImport(c.namedBindings)) names.add(c.namedBindings.name.text);
          else for (const el of c.namedBindings.elements) names.add(el.name.text);
        }
      }
    }
    // const cp = require("child_process") / const { exec } = require("child_process")
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isCallExpression(node.initializer)
        && calleeName(node.initializer.expression) === "require"
        && node.initializer.arguments.length && ts.isStringLiteral(node.initializer.arguments[0])
        && CHILD_PROCESS_MODULES.has(node.initializer.arguments[0].text)) {
      if (ts.isIdentifier(node.name)) names.add(node.name.text);
      else if (ts.isObjectBindingPattern(node.name))
        for (const el of node.name.elements) if (ts.isIdentifier(el.name)) names.add(el.name.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return names;
}

/** A function that renders JSX is a UI component, not a prompt-construction sink. */
function rendersJsx(fnNode) {
  let found = false;
  const scan = (n) => {
    if (found) return;
    if (ts.isJsxElement(n) || ts.isJsxSelfClosingElement(n) || ts.isJsxFragment(n)) { found = true; return; }
    ts.forEachChild(n, scan);
  };
  if (fnNode.body) scan(fnNode.body);
  return found;
}

/**
 * Does this function actually interpolate untrusted input INTO a string? Name matching alone
 * flags every UI component called `*Prompt*`; requiring real interpolation is what makes RT-1
 * a signal instead of noise.
 */
function interpolatesUntrusted(fnNode, sf) {
  let found = false;
  const scan = (n) => {
    if (found) return;
    if (ts.isTemplateExpression(n)) {
      for (const span of n.templateSpans)
        if (anyHint(span.expression.getText(sf), UNTRUSTED_HINTS)) { found = true; return; }
    }
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const stringish = ts.isStringLiteral(n.left) || ts.isStringLiteral(n.right)
        || ts.isTemplateExpression(n.left) || ts.isTemplateExpression(n.right);
      if (stringish && (anyHint(n.left.getText(sf), UNTRUSTED_HINTS) || anyHint(n.right.getText(sf), UNTRUSTED_HINTS))) {
        found = true; return;
      }
    }
    ts.forEachChild(n, scan);
  };
  if (fnNode.body) scan(fnNode.body);
  return found;
}

function analyzeFile(absPath, root, out) {
  let srcText;
  try { srcText = fs.readFileSync(absPath, "utf8"); } catch { return; }
  const rel = path.relative(root, absPath) || path.basename(absPath);
  let sf;
  try {
    sf = ts.createSourceFile(absPath, srcText, ts.ScriptTarget.Latest, /*setParentNodes*/ true,
      absPath.endsWith(".tsx") || absPath.endsWith(".jsx") ? ts.ScriptKind.TSX : undefined);
  } catch { return; }

  const procNames = collectProcessBindings(sf);   // identifiers actually bound to child_process
  const lineOf = (node) => sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
  const snippet = (node) => {
    const ln = lineOf(node);
    const text = (srcText.split(/\r?\n/)[ln - 1] || "").trim();
    return text.slice(0, 160);
  };
  const add = (rt, severity, node, why) =>
    out.push({ rt, severity, file: rel, line: lineOf(node), why, snippet: snippet(node) });

  // resolve the nearest enclosing named function for a node
  function enclosingFnName(node) {
    let cur = node.parent;
    while (cur) {
      if (ts.isFunctionDeclaration(cur) && cur.name) return cur.name.text;
      if (ts.isMethodDeclaration(cur) && cur.name && ts.isIdentifier(cur.name)) return cur.name.text;
      if ((ts.isFunctionExpression(cur) || ts.isArrowFunction(cur)) &&
          cur.parent && ts.isVariableDeclaration(cur.parent) && ts.isIdentifier(cur.parent.name))
        return cur.parent.name.text;
      cur = cur.parent;
    }
    return "";
  }

  function visitCall(node) {
    const dotted = calleeName(node.expression);
    const leaf = lastSeg(dotted);
    const rootId = dotted.split(".")[0];

    // RT-3: command execution — resolved via imports, NOT bare method names.
    // `/re/.exec(s)` and `Scope.fork()` must not count as command execution.
    const isRealProcCall =
      (EXEC_METHODS.has(leaf) && (procNames.has(rootId) || procNames.has(dotted))) ||
      KNOWN_PROC_CALLS.has(dotted);
    if (isRealProcCall) {
      const argText = node.arguments.map((a) => a.getText(sf)).join(", ");
      const sev = /shell\s*:\s*true/.test(argText) ? "crit" : "high";
      add("RT-3", sev, node, `command execution ${dotted}() — candidate: do tools run un-isolated? confirm the sandbox dynamically`);
    }
    if (dotted === "eval") add("RT-3", "crit", node, "eval() dynamic execution — candidate: can the executed content be influenced by untrusted input?");

    // RT-7: dynamic require()/import() with a non-literal argument
    if ((leaf === "require") && node.arguments.length && !ts.isStringLiteral(node.arguments[0]))
      add("RT-7", "high", node, "dynamic require() — candidate: does the module name come from an external/untrusted source (supply chain)?");

    // RT-8: logging suspected credentials
    if (dotted.startsWith("console.") && node.arguments.some((a) => anyHint(a.getText(sf), SECRET_HINTS)))
      add("RT-8", "high", node, "suspected credential/env var written to a log/output — candidate: data exfiltration");

    // RT-6: writing untrusted content into a persistent-memory file
    if (WRITE_METHODS.has(leaf)) {
      const argText = node.arguments.map((a) => a.getText(sf)).join(", ");
      if (anyHint(argText, MEMORY_HINTS))
        add("RT-6", "crit", node, `${dotted}() writes into a persistent-memory file — candidate: is the source trusted / provenance-checked (memory poisoning)?`);
    }
  }

  function visitNewExpr(node) {
    if (calleeName(node.expression) === "Function")
      add("RT-3", "crit", node, "new Function() builds code from a string — candidate: dynamic execution of untrusted content");
  }

  // RT-7 (dynamic import expression), plus function-level heuristics
  function visitFunctionLike(node) {
    let name = "";
    if ((ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) && node.name && ts.isIdentifier(node.name)) name = node.name.text;
    else if ((ts.isFunctionExpression(node) || ts.isArrowFunction(node)) &&
             node.parent && ts.isVariableDeclaration(node.parent) && ts.isIdentifier(node.parent.name)) name = node.parent.name.text;
    if (!name) return;
    const body = node.body ? node.body.getText(sf) : "";
    const lname = lower(name);

    if (MEMORY_FN.some((h) => lname.includes(h)) && /\.(write|append)|writeFile|appendFile|writeFileSync/.test(body))
      add("RT-6", "crit", node, `function ${name}() appears to write content into persistent memory — candidate: is the source trusted / provenance-checked (memory poisoning)?`);

    if (GUARD_NAME.some((h) => lname.includes(h)) && /\.(test|match|exec|replace)\(|new RegExp|includes\(|indexOf\(/.test(body))
      add("RT-GUARD", "high", node, `function ${name}() appears to block by signature/keyword — candidate: a semantic injection (disguised as benign content) may bypass it`);

    // RT-1: name match alone flags every UI component called *Prompt*; require that untrusted
    // input is ACTUALLY interpolated into a string.
    if (PROMPT_FN.some((h) => lname.includes(h)) && !rendersJsx(node) && interpolatesUntrusted(node, sf))
      add("RT-1", "high", node, `function ${name}() interpolates external content into a prompt/instruction — candidate: prompt injection`);
  }

  function visit(node) {
    if (ts.isCallExpression(node)) {
      // dynamic import(): CallExpression whose expression is the `import` keyword
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword && node.arguments.length && !ts.isStringLiteral(node.arguments[0]))
        add("RT-7", "high", node, "dynamic import() — candidate: does the module specifier come from an external/untrusted source (supply chain)?");
      else visitCall(node);
    } else if (ts.isNewExpression(node)) {
      visitNewExpr(node);
    }
    if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node))
      visitFunctionLike(node);
    ts.forEachChild(node, visit);
  }
  visit(sf);
}

// ── main ──────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
const sIdx = argv.indexOf("--source");
const source = sIdx >= 0 ? argv[sIdx + 1] : null;
if (!source) { process.stderr.write("usage: node analyze.mjs --source <dir> [--json]\n"); process.exit(2); }

const root = path.resolve(source);
const files = fs.existsSync(root) && fs.statSync(root).isDirectory() ? walk(root) : [root];
const out = [];
for (const f of files) analyzeFile(f, root, out);

const order = { crit: 0, high: 1, med: 2 };
out.sort((a, b) => (order[a.severity] ?? 3) - (order[b.severity] ?? 3) || a.rt.localeCompare(b.rt) || a.file.localeCompare(b.file) || a.line - b.line);

process.stdout.write(JSON.stringify({
  engine: "TrustShell static v0 (ts/js)",
  note: "candidate paths (triage) — dynamic red-team must confirm/refute. candidate != vulnerability.",
  source: root,
  count: out.length,
  candidates: out,
}, null, 2));
