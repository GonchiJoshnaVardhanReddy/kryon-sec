"""A9 live runner — the model half of the evaluation, for the operator to run.

``test_hypothesis_eval_a9.py`` scores the prompt offline: it proves the
evidence block and the task text hold every property the rubric needs. It
cannot say whether a model, reading them, actually produces better
hypotheses — that needs a model. This script supplies the missing half.

It renders the *same ten fixtures* through the *same* current prompt, sends
each to the configured provider, and scores the answer with the *same* seven
criteria, so the numbers line up with the offline report.

It also runs the pre-A4 baseline prompt against the same fixtures, if you
ask for it, using the same model and settings — that is the before/after the
A9 spec asks for, and this is the only place it can be measured.

**It costs money and it talks to a third party.** So it does nothing until
told twice::

    py -3.13 tests/a9_live_runner.py                 # prints the plan, exits
    py -3.13 tests/a9_live_runner.py --run            # current prompt only
    py -3.13 tests/a9_live_runner.py --run --baseline # both, for a comparison
    py -3.13 tests/a9_live_runner.py --run --model gpt-4o-mini

What it sends: the ten synthetic fixtures below and nothing else. No
engagement data, no customer data, no real target — every value in the
fixtures is invented (``target-corp.example`` is reserved for documentation).
What it writes: ``a9-live-results.json`` next to wherever you run it, plus a
readable table on stdout.

Read the report's "reproducibility" section before running this; the model
name it records is what makes the numbers comparable between runs.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# The runner lives beside the evaluation it complements and imports its
# fixtures, prompt checks and rubric from it — one definition of each, so
# the offline and live halves cannot drift apart.
sys.path.insert(0, str(Path(__file__).parent))

from test_hypothesis_eval_a9 import (  # noqa: E402
    _CRITERIA,
    GOOD_EXAMPLES,
    FIXTURES,
    make_evidence,
    render_baseline_prompt,
    score_set,
    summarise,
)

from kryonsec.config import load_config  # noqa: E402
from kryonsec.purple.hypothesize import (  # noqa: E402
    PROMPT_VERSION,
    propose_hypotheses_with_model,
    render_hypothesize_prompt,
)

RESULTS_PATH = Path("a9-live-results.json")


def plan(cfg, args) -> str:
    """What a --run would do, spelled out before it does it."""
    provider = getattr(cfg, "provider", "?")
    model = args.model or getattr(cfg, "chat_model", None) or "(provider default)"
    renders = len(FIXTURES) * (2 if args.baseline else 1)
    return (
        f"provider      : {provider}\n"
        f"model         : {model}\n"
        f"fixtures      : {len(FIXTURES)} ({', '.join(f.key for f in FIXTURES)})\n"
        f"prompts sent  : {renders}"
        f"{' (current + pre-A4 baseline, same model)' if args.baseline else ''}\n"
        f"cost          : {renders} paid completion calls\n"
        f"writes        : {RESULTS_PATH.resolve()}\n"
        f"prompt version: {PROMPT_VERSION}"
    )


def score_one(cfg, fixture, prompt: str, model: str | None, label: str) -> dict:
    """One prompt, one model call, one rubric sweep."""
    result, served_by = propose_hypotheses_with_model(cfg, prompt)
    evidence = make_evidence(fixture)
    scored = score_set(result, evidence)
    return {
        "fixture": fixture.key,
        "what": fixture.what,
        "arm": label,  # "current" or "baseline"
        "model": served_by or model or "unknown",
        "hypotheses": result.model_dump(),
        "scores": {h_id: [{"criterion": r.criterion, "passed": r.passed,
                           "reason": r.reason, "evidence": r.evidence}
                          for r in results]
                   for h_id, results in scored.items()},
        "summary": summarise(scored),
    }


def table(runs: list[dict]) -> str:
    """Per-criterion pass rate, per arm, across every hypothesis scored."""
    arms: dict[str, dict[str, list[int]]] = {}
    for run in runs:
        tally = arms.setdefault(run["arm"], {c: [0, 0] for c in _CRITERIA})
        for results in run["scores"].values():
            for r in results:
                tally[r["criterion"]][1] += 1
                tally[r["criterion"]][0] += bool(r["passed"])

    width = max(len(c) for c in _CRITERIA)
    header = f"{'criterion':<{width}}  " + "  ".join(
        f"{arm:>10}" for arm in arms)
    rows = [header, "-" * len(header)]
    for criterion in _CRITERIA:
        cells = []
        for arm in arms:
            passed, total = arms[arm][criterion]
            rate = f"{passed}/{total}" if total else "n/a"
            cells.append(f"{rate:>10}")
        rows.append(f"{criterion:<{width}}  " + "  ".join(cells))

    rows.append("")
    for arm in arms:
        counts = [len(r["hypotheses"]["hypotheses"]) for r in runs
                  if r["arm"] == arm]
        rows.append(f"{arm}: {sum(counts)} hypotheses proposed across "
                    f"{len(counts)} fixtures")
    return "\n".join(rows)


def failures(runs: list[dict], limit: int = 15) -> str:
    """Every failed criterion, with its reason and evidence reference — the
    part a human actually reads."""
    rows = []
    for run in runs:
        for h_id, results in run["scores"].items():
            for r in results:
                if not r["passed"]:
                    rows.append(f"[{run['arm']}/{run['fixture']}/{h_id}] "
                                f"{r['criterion']}: {r['reason']}\n"
                                f"    evidence: {r['evidence'][:200]}")
    if not rows:
        return "no criterion failed on any hypothesis."
    return "\n".join(rows[:limit]) + (
        f"\n... and {len(rows) - limit} more" if len(rows) > limit else "")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run", action="store_true",
                        help="actually call the provider (default: plan only)")
    parser.add_argument("--baseline", action="store_true",
                        help="also run the pre-A4 baseline prompt")
    parser.add_argument("--model", default=None,
                        help="override the configured chat model")
    parser.add_argument("--only", action="append", default=None,
                        help="restrict to these fixture keys (repeatable)")
    args = parser.parse_args()

    cfg = load_config()
    if args.model:
        cfg.chat_model = args.model

    chosen = [f for f in FIXTURES
              if not args.only or f.key in args.only]
    if not chosen:
        print(f"no fixture matched --only {args.only}", file=sys.stderr)
        return 2

    print(plan(cfg, args))
    if not args.run:
        print("\nThis was a plan only. Add --run to make the calls "
              "(they cost money).")
        return 0

    runs: list[dict] = []
    for fixture in chosen:
        for label, render in (
            ("current", lambda f=fixture: render_hypothesize_prompt(f.graph())),
            *((("baseline", lambda f=fixture: render_baseline_prompt(f.graph())),)
              if args.baseline else ()),
        ):
            print(f"  {label:<9} {fixture.key} ...", flush=True)
            try:
                runs.append(score_one(cfg, fixture, render(), args.model, label))
            except Exception as e:
                # A provider that fails must be reported, never papered over:
                # a run with half its fixtures missing is not a result.
                print(f"    FAILED: {type(e).__name__}: {e}", flush=True)
                runs.append({"fixture": fixture.key, "arm": label,
                             "error": f"{type(e).__name__}: {e}",
                             "scores": {}, "hypotheses": {"hypotheses": []},
                             "summary": {}})

    print("\n" + table(runs))
    print("\nfailed criteria:\n" + failures(runs))

    RESULTS_PATH.write_text(json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(),
        "prompt_version": PROMPT_VERSION,
        "provider": getattr(cfg, "provider", None),
        "model": args.model or getattr(cfg, "chat_model", None),
        "fixtures": [f.key for f in chosen],
        "runs": runs,
    }, indent=2), encoding="utf-8")
    print(f"\nwrote {RESULTS_PATH.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
