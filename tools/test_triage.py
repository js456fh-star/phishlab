#!/usr/bin/env python3
"""Minimal self-test for the triage toolkit — run: python3 -I tools/test_triage.py"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("triage", os.path.join(HERE, "triage.py"))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)

fails = []


def check(name, cond):
    print(("  PASS  " if cond else "  FAIL  ") + name)
    if not cond:
        fails.append(name)


# levenshtein sanity
check("levenshtein identical = 0", t.levenshtein("abc", "abc") == 0)
check("levenshtein freight typo = 2",
      t.levenshtein("halvorsen-frieght.com", "halvorsen-freight.com") == 2)

# defang does not double-bracket
check("defang idempotent on defanged input",
      t.defang("evil[.]com") == "evil[.]com")
check("defang neutralizes raw domain",
      "[.]" in t.defang("evil.com"))
check("defang keeps file extensions readable",
      t.defang("report.json").endswith(".json"))

# header scoring reaches MALICIOUS
score, verdict = t.header_analysis()
check("email scored MALICIOUS", verdict == "MALICIOUS")
check("score above threshold", score >= 60)

# impossible travel distance US->RO is large
check("geo distance US->RO > 7000km", t.geo_distance_km("US", "RO") > 7000)

print()
if fails:
    print(f"{len(fails)} test(s) failed")
    sys.exit(1)
print("all tests passed")
