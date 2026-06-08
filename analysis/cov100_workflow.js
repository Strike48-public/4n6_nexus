export const meta = {
  name: 'coverage-to-100',
  description: 'Fan out one agent per module to write TDD tests for uncovered lines, then gate on full suite + F1=1.00',
  phases: [
    { title: 'Cover', detail: 'one agent per module writes tests for its uncovered lines' },
  ],
}

// args: [{module, short, missing:[int...]}, ...]
const modules = typeof args === 'string' ? JSON.parse(args) : args

const SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['module', 'test_file', 'lines_targeted', 'lines_remaining', 'module_pct_after', 'full_suite_green'],
  properties: {
    module: { type: 'string' },
    test_file: { type: 'string', description: 'relative path of the test file written' },
    lines_targeted: { type: 'integer', description: 'how many previously-uncovered lines the new tests now exercise' },
    lines_remaining: {
      type: 'array',
      description: 'lines still uncovered after the new tests',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['line', 'reason', 'needs_pragma'],
        properties: {
          line: { type: 'integer' },
          reason: { type: 'string' },
          needs_pragma: { type: 'boolean', description: 'true if the line is a genuinely-unreachable defensive guard / unavailable-library path deserving pragma: no cover' },
        },
      },
    },
    module_pct_after: { type: 'number', description: 'coverage percent for THIS module after the new tests' },
    full_suite_green: { type: 'boolean', description: 'did PYTHONPATH=. python3 -m pytest <new test file> -q pass' },
    notes: { type: 'string' },
  },
}

function promptFor(m) {
  const safe = m.short.replace(/[\/.]/g, '_').replace(/_py$/, '')
  const testFile = `tests/test_${safe}_cov.py`
  return `You are raising unit-test coverage of ONE module to 100% on the SIFT "find evil" DFIR detection engine (pure-Python, pytest).

TARGET MODULE: ${m.module}
UNCOVERED LINES (line numbers in that file): ${JSON.stringify(m.missing)}

YOUR DEDICATED TEST FILE (create it, you own it exclusively — no other agent writes here): ${testFile}

NON-NEGOTIABLE RULES:
1. TESTS ONLY. Do NOT edit any file under sift_find_evil/ and do NOT edit pyproject.toml or any config. If a line is genuinely untestable (an unreachable defensive guard, or a path that requires an unavailable forensic library such as pyewf/pypff/volatility3 that cannot be mocked cleanly), DO NOT touch the source — instead report it in lines_remaining with needs_pragma=true and a precise one-line reason. The orchestrator applies pragmas centrally.
2. Write your tests ONLY in ${testFile}. Do not edit other tests/ files (other agents own them).
3. Mirror the existing test style in tests/ (look at the module's existing tests/test_*.py for fixtures, helpers, import patterns, and how dataclasses like Finding are constructed). Many parsers/detectors use frozen dataclasses and Protocol-based duck typing so you can pass lightweight fakes/mocks — prefer that over real forensic libraries.
4. Reproduce real behavior: read the actual source around each uncovered line to understand WHAT branch/guard/error-path it is, then write a test that genuinely drives execution through it. Do not write vacuous asserts. Use monkeypatch / unittest.mock for subprocess, missing-import guards, and filesystem edges. Use tmp_path for file IO.

WORKFLOW:
- Read ${m.module} (focus on the uncovered lines and their enclosing functions).
- Read the module's existing test file(s) in tests/ to match conventions and reuse helpers.
- Write ${testFile} with focused tests covering as many of the uncovered lines as are genuinely reachable.
- Verify: run \`PYTHONPATH=. python3 -m pytest ${testFile} -q\` until green.
- Measure: run \`PYTHONPATH=. python3 -m pytest ${testFile} tests/test_${safe}.py --cov=${m.module} --cov-report=term-missing -q\` (drop the second path if that test file does not exist) and read the module's remaining missing lines from the report. Note: the project excludes "..." Protocol stubs and "if TYPE_CHECKING" already.
- Report precisely. lines_remaining must list every line from the target set that is STILL uncovered, each with a reason and needs_pragma flag.

Return the structured object. test_file must be "${testFile}".`
}

const results = await parallel(
  modules.map((m) => () =>
    agent(promptFor(m), {
      label: `cov:${m.short}`,
      phase: 'Cover',
      schema: SCHEMA,
    }).then((r) => r && { ...r, _missing_input: m.missing })
  )
)

const ok = results.filter(Boolean)
const fully = ok.filter((r) => r.lines_remaining.length === 0)
const pragmaLines = ok.flatMap((r) =>
  r.lines_remaining.filter((l) => l.needs_pragma).map((l) => ({ module: r.module, ...l }))
)
const stillOpen = ok.flatMap((r) =>
  r.lines_remaining.filter((l) => !l.needs_pragma).map((l) => ({ module: r.module, ...l }))
)

return {
  agents: results.length,
  succeeded: ok.length,
  fully_covered_modules: fully.length,
  modules_with_pragma_candidates: ok.filter((r) => r.lines_remaining.some((l) => l.needs_pragma)).length,
  pragma_lines: pragmaLines,
  still_open_lines: stillOpen,
  per_module: ok.map((r) => ({
    module: r.module,
    test_file: r.test_file,
    targeted: r.lines_targeted,
    remaining: r.lines_remaining.length,
    pct: r.module_pct_after,
    green: r.full_suite_green,
  })),
}
