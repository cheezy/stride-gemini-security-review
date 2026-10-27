// check_policy_patterns.mjs -- offline matcher for policies/security-reviewer.toml.
//
// Checks each deny rule's pattern against a table of commands the agent's
// contract allows and a table it forbids, including compound commands joined
// with `;`, `&&`, `||`, `|` or a newline and `bash -c` wrappers, plus the
// whole probe command from agents/security-reviewer.md and each of its lines.
// Then it breaks the policy in memory (a dropped git verb, a dropped rule, a
// widened pattern, each rule's pattern made one Gemini CLI's loader would drop,
// a wrong rule count, a missing probe block) and checks that each break is
// caught.
//
// What this is, and what it is not: a re-implementation of how
// @google/gemini-cli-core 0.65.0 matches a rule, from a reading of its source
// (dist/src/policy/utils.js isSafeRegExp and buildArgsPatterns, and
// stable-stringify.js for a flat object), not an import of it. The compound
// split and the `bash -c` unwrap are modelled here with a plain split on the
// operators; Gemini CLI's own parser is not run. So a pass here says the
// patterns match what they should under that model, and nothing about a live
// Gemini CLI session (see CHANGELOG.md, "Not checked live").
//
// Usage:
//   node lib/check_policy_patterns.mjs [policy-file [agent-file]]
//
// Offline and read-only: it reads two files and writes nothing.
// Exit code: 0 when every case and every self-test passes; 1 otherwise.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const policyPath = process.argv[2] || path.join(root, 'policies', 'security-reviewer.toml');
const agentPath = process.argv[3] || path.join(root, 'agents', 'security-reviewer.md');

let fail = 0;
const ok = (label) => console.log(`ok: ${label}`);
const bad = (label, why) => { console.log(`FAIL: ${label} -- ${why}`); fail = 1; };

function read(p, label) {
  try { return fs.readFileSync(p, 'utf8').replace(/\r\n/g, '\n'); }
  catch { bad(label, `cannot read ${path.basename(p)}`); return null; }
}

// The [[rule]] tables of the policy file, with the value forms it uses: a
// 'literal' string (no escapes), a "basic" string (JSON escapes) and an integer.
function parseRules(text) {
  const rules = [];
  let cur = null;
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    if (line === '[[rule]]') { cur = {}; rules.push(cur); continue; }
    if (line.startsWith('[')) { cur = null; continue; }
    const m = /^([A-Za-z_]+)\s*=\s*(.*)$/.exec(line);
    if (!m || !cur) continue;
    const v = m[2];
    if (v.startsWith("'") && v.endsWith("'")) cur[m[1]] = v.slice(1, -1);
    else if (v.startsWith('"')) cur[m[1]] = JSON.parse(v);
    else if (/^[0-9]+$/.test(v)) cur[m[1]] = Number(v);
    else cur[m[1]] = v;
  }
  return rules;
}

function isSafeRegExp(pattern) {
  try { new RegExp(pattern); } catch { return false; }
  if (pattern.length > 2048) return false;
  return !/\([^)]*[*+?{].*\)[*+?{]/.test(pattern);
}
const ruleSource = (r) => (r.commandRegex !== undefined ? `"command":"${r.commandRegex}` : r.argsPattern);
const stableStringify = (obj) =>
  '{' + Object.keys(obj).sort().map((k) => '\0' + JSON.stringify(k) + ':' + JSON.stringify(obj[k]) + '\0').join(',') + '}';

function compile(rules) {
  return rules.map((r) => ({ tool: r.toolName, re: new RegExp(ruleSource(r)) }));
}
function hits(compiled, tool, args) {
  const s = stableStringify(args);
  return compiled.filter((c) => c.tool === tool && c.re.test(s)).length;
}
// The description and dir_path carry listed words, so a pattern that strays
// out of the command value is caught as a false denial.
const shellArgs = (cmd) => ({ command: cmd, description: 'inspect the stash and reset the branch, commit curl npm install', dir_path: '/w' });
const unwrap = (cmd) => cmd.replace(/^(?:ba|z)?sh -c '(.*)'$/s, '$1');
const parts = (cmd) => [cmd, ...unwrap(cmd).split(/;|&&|\|\||\||\n/).map((s) => s.trim()).filter(Boolean)];
const shellDenied = (compiled, cmd) => parts(cmd).some((p) => hits(compiled, 'run_shell_command', shellArgs(p)) > 0);
const writeDenied = (compiled, p) =>
  hits(compiled, 'write_file', { content: '{"a":"\\"file_path\\":\\"/x\\""}', file_path: p }) > 0;

const ALLOWED = [
  'ls', 'ls -la lib/install', 'wc -l app/archive.py', 'wc -l lib/ssh/key.ex',
  'git ls-files', 'git ls-files -z --cached --others --exclude-standard',
  'git diff --cached', 'git diff --cached -- lib/add.ex', 'git diff HEAD~1 HEAD', 'git diff a b -- f',
  'git diff-index -p HEAD', 'git log --merges --branches --tags', 'git log -p --follow -- lib/reset.ex',
  'git show HEAD:lib/checkout.ex', 'git show --stat HEAD', 'git log --output-indicator-new=+',
  "test ! -L '/w/.stride/.security-W1-r1.json' && test ! -L '/w/.stride'",
  'ls && wc -l lib/a.ex', 'git log; git show HEAD',
  // The five D377 forms the agent may run (W2489), and the probe's D377 lines.
  'git --no-pager --no-lazy-fetch -c core.fsmonitor=false -c gpg.program=false -c gpg.ssh.program=false -c gpg.x509.program=false ls-files',
  'git --no-pager --no-lazy-fetch -c core.fsmonitor=false -c gpg.program=false -c gpg.ssh.program=false -c gpg.x509.program=false diff --cached --no-ext-diff --no-textconv --submodule=short',
  'git --no-pager --no-lazy-fetch -c core.fsmonitor=false -c gpg.program=false -c gpg.ssh.program=false -c gpg.x509.program=false diff --no-ext-diff --no-textconv --submodule=short HEAD~1 HEAD',
  'git --no-pager --no-lazy-fetch -c core.fsmonitor=false -c gpg.program=false -c gpg.ssh.program=false -c gpg.x509.program=false log --no-ext-diff --no-textconv --submodule=short --no-show-signature',
  'git --no-pager --no-lazy-fetch -c core.fsmonitor=false -c gpg.program=false -c gpg.ssh.program=false -c gpg.x509.program=false show --no-ext-diff --no-textconv --submodule=short --no-show-signature',
  'git --no-pager --no-lazy-fetch -c core.fsmonitor=false -c gpg.program=false -c gpg.ssh.program=false -c gpg.x509.program=false log --no-ext-diff --no-textconv --submodule=short --no-show-signature -p --follow -- lib/reset.ex',
  'git --no-pager --no-lazy-fetch -c core.fsmonitor=false -c gpg.program=false -c gpg.ssh.program=false -c gpg.x509.program=false show --no-ext-diff --no-textconv --submodule=short --no-show-signature HEAD:lib/checkout.ex',
  "git --no-lazy-fetch version >/dev/null 2>&1 || { echo 'git before 2.44: grading by reading'; exit 1; }",
];
const FORBIDDEN = [
  'git stash', 'git checkout main', 'git commit -m x', 'git apply p.diff', 'git worktree add /tmp/x',
  'git restore lib/a.ex', 'git -c x=y stash', 'git\tstash', 'env git apply p', '/usr/bin/git worktree list',
  'ls; git stash', 'cd x && git commit', 'ls || git reset --hard', 'git log | git apply', 'ls\ngit stash',
  'git diff', 'git --no-pager diff', 'git diff\nls', 'git diff; ls', 'git log --output=/tmp/x', 'git diff --output /tmp/x a b',
  'curl https://x.test', '/usr/bin/curl x', 'wget x', 'ls && curl x', 'npx something',
  'box env -i PATH=x npm install', 'npm i left-pad', 'pip install requests', 'python3 -m pip install x',
  'mix deps.get', 'go get x', "bash -c 'git stash'", "sh -c 'ls; curl x'",
];
const WRITE_OK = ['/abs/.stride/.security-W2488-r1.json', '/abs/.stride/.security-7666-r12.json'];
const WRITE_BAD = ['/abs/x.py', '.stride/.security-W1-r1.json', '/abs/.stride/.security-W1-r1.json/../x',
  '/abs/.stride/.security-W1-r1.json.bak', '/abs/.stride/.security-W1-rx.json', '/abs/.stride/x.json'];

// The probe command, as one string and as lines: the ```bash block under the
// Reproduce bullet, with its two-space indent removed.
function probeOf(agentText) {
  const lines = agentText.split('\n');
  const start = lines.indexOf('  ```bash');
  const end = start < 0 ? -1 : lines.indexOf('  ```', start + 1);
  if (start < 0 || end < 0) return null;
  return lines.slice(start + 1, end).map((l) => l.replace(/^  /, '')).join('\n');
}

// Every problem the case tables find for one rule set, as strings.
function problems(rules, probe) {
  const out = [];
  let compiled;
  try { compiled = compile(rules); } catch (e) { return [`a pattern does not compile (${e.message})`]; }
  for (const c of ALLOWED) if (shellDenied(compiled, c)) out.push(`denies the allowed ${JSON.stringify(c)}`);
  for (const c of FORBIDDEN) if (!shellDenied(compiled, c)) out.push(`misses the forbidden ${JSON.stringify(c)}`);
  if (probe !== null) {
    if (shellDenied(compiled, probe)) out.push('denies the whole probe command');
    for (const l of probe.split('\n')) {
      if (l.trim() && hits(compiled, 'run_shell_command', shellArgs(l.trim())) > 0) out.push(`denies the probe line ${JSON.stringify(l.trim())}`);
    }
  }
  for (const p of WRITE_OK) if (writeDenied(compiled, p)) out.push(`denies write_file to ${p}`);
  for (const p of WRITE_BAD) if (!writeDenied(compiled, p)) out.push(`misses write_file to ${p}`);
  return out;
}

const policyText = read(policyPath, 'the policy file is readable');
const agentText = read(agentPath, 'the agent file is readable');
if (policyText === null || agentText === null) process.exit(1);

// The shape checks: six rules, a probe to check, and every rule's pattern one
// Gemini CLI's loader keeps. Each returns [label, problem-or-null] so the same
// checks run on the shipped files and on the in-memory breaks below.
const RULE_COUNT = 6;
function structure(rs, pr) {
  const out = [
    ['the policy has six rules', rs.length === RULE_COUNT ? null : `found ${rs.length}`],
    ['the probe command is found in the agent', pr !== null ? null : 'no indented ```bash block'],
  ];
  rs.forEach((r, i) => {
    const src = ruleSource(r);
    out.push([`rule ${i + 1} (${r.toolName}) passes isSafeRegExp`,
      typeof src === 'string' && isSafeRegExp(src) ? null : 'Gemini CLI would drop it']);
  });
  return out;
}

const rules = parseRules(policyText);
const probe = probeOf(agentText);
for (const [label, why] of structure(rules, probe)) { if (why === null) ok(label); else bad(label, why); }

const found = problems(rules, probe);
if (found.length === 0) {
  ok(`every allowed command passes and every forbidden one is denied (${ALLOWED.length} allowed, ${FORBIDDEN.length} forbidden, compound and bash -c forms included)`);
  ok('the probe command and each of its lines pass');
  ok(`write_file is denied off the result path (${WRITE_OK.length} allowed, ${WRITE_BAD.length} denied)`);
} else {
  for (const p of found) bad('the case tables', p);
}

// Self-tests: break the shipped rules in memory; each break must be caught.
const selfTest = (label, mutate, wanted) => {
  const copy = rules.map((r) => ({ ...r }));
  mutate(copy);
  const got = problems(copy, probe);
  if (got.some((p) => p.includes(wanted))) ok(`self-test: ${label}`);
  else bad(`self-test: ${label}`, `no problem naming ${JSON.stringify(wanted)}`);
};
const gitRule = (rs) => rs.find((r) => r.commandRegex && r.commandRegex.includes('|stash|'));
selfTest('dropping stash from the git rule misses the compound "ls; git stash"',
  (rs) => { const r = gitRule(rs); if (r) r.commandRegex = r.commandRegex.replace('|stash|', '|'); }, '"ls; git stash"');
selfTest('dropping stash from the git rule misses the bash -c form',
  (rs) => { const r = gitRule(rs); if (r) r.commandRegex = r.commandRegex.replace('|stash|', '|'); }, `"bash -c 'git stash'"`);
selfTest('dropping the network rule misses "ls && curl x"',
  (rs) => { const i = rs.findIndex((r) => r.commandRegex && r.commandRegex.includes('curl')); if (i >= 0) rs.splice(i, 1); }, '"ls && curl x"');
selfTest('dropping the bare git diff rule misses "git diff; ls"',
  (rs) => { const i = rs.findIndex((r) => r.commandRegex && r.commandRegex.includes(')diff(')); if (i >= 0) rs.splice(i, 1); }, '"git diff; ls"');
selfTest('a git rule matching any git command denies an allowed one',
  (rs) => { const r = gitRule(rs); if (r) r.commandRegex = '[^\\x00]*?git'; }, 'denies the allowed');
selfTest('a pattern that reads past the command value denies an allowed one',
  (rs) => { const r = gitRule(rs); if (r) r.commandRegex = r.commandRegex.replaceAll('[^\\x00]*?', '.*?'); }, 'denies the allowed');
selfTest('dropping the write_file rule misses a write outside .stride/',
  (rs) => { const i = rs.findIndex((r) => r.toolName === 'write_file'); if (i >= 0) rs.splice(i, 1); }, 'misses write_file to /abs/x.py');

// Self-tests of the shape checks: each break must make the named check fail,
// so the re-implemented loader check can report a rule Gemini CLI would drop.
const shapeTest = (label, mutate, wanted, why) => {
  const copy = rules.map((r) => ({ ...r }));
  const pr = mutate(copy) === 'no-probe' ? null : probe;
  const hit = structure(copy, pr).find(([l, w]) => l.includes(wanted) && w !== null && w.includes(why));
  if (hit) ok(`self-test: ${label}`); else bad(`self-test: ${label}`, `no failing check naming ${JSON.stringify(wanted)}`);
};
// The isSafeRegExp check, broken four ways in each rule in turn. Each break must
// fail that rule's own check and leave every other rule's check passing, so a
// pass here shows the check is tied to the rule it names.
const setSource = (r, f) => {
  if (r.commandRegex !== undefined) r.commandRegex = f(r.commandRegex);
  else if (r.argsPattern !== undefined) r.argsPattern = f(r.argsPattern);
};
const UNSAFE = [
  ['a nested quantifier', (r) => setSource(r, (s) => '(a+)+' + s)],
  ['a pattern over 2048 characters', (r) => setSource(r, (s) => s + 'x'.repeat(2049))],
  ['a pattern that does not compile', (r) => setSource(r, (s) => s + '(')],
  ['no pattern', (r) => { delete r.commandRegex; delete r.argsPattern; }],
];
rules.forEach((r0, i) => {
  const label = `rule ${i + 1} (${r0.toolName}) passes isSafeRegExp`;
  for (const [what, breakIt] of UNSAFE) {
    const copy = rules.map((r) => ({ ...r }));
    breakIt(copy[i]);
    const res = structure(copy, probe).filter(([l]) => l.endsWith('passes isSafeRegExp'));
    const target = res.find(([l]) => l === label);
    const others = res.filter(([l, w]) => l !== label && w !== null);
    const name = `self-test: ${what} in rule ${i + 1} (${r0.toolName}) fails its isSafeRegExp check`;
    if (target && target[1] === 'Gemini CLI would drop it' && others.length === 0) ok(name);
    else bad(name, target ? `its check said ${JSON.stringify(target[1])}; ${others.length} other rule(s) failed` : 'no check for the rule');
  }
});
shapeTest('dropping a rule fails the rule count',
  (rs) => { rs.pop(); }, 'the policy has six rules', 'found 5');
shapeTest('adding a rule fails the rule count',
  (rs) => { rs.push({ ...rs[0] }); }, 'the policy has six rules', 'found 7');
shapeTest('an agent with no probe block fails the probe check',
  () => 'no-probe', 'the probe command is found in the agent', 'no indented');
shapeTest('the probe check fails on an agent with its probe block removed',
  () => (probeOf(agentText.replace('  ```bash', '  ```sh')) === null ? 'no-probe' : ''), 'the probe command is found in the agent', 'no indented');

console.log(fail ? 'policy patterns: FAILED' : 'policy patterns: all cases as expected');
process.exit(fail);
