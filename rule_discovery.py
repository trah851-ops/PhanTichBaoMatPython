#!/usr/bin/env python3
"""
rule_discovery.py
Simple tool to scan a set of Python files and produce candidate rule patterns based on heuristics.
Usage:
  python rule_discovery.py path/to/dir_or_file [--out candidates.json] [--min-count N]
The tool will look for:
 - repeated literal patterns that often correlate with issues (e.g., open without with)
 - TODO/FIXME occurrences
 - repeated use of certain dangerous calls
It produces a JSON list of suggested rule objects for review.
Note: This is a helper — suggestions must be reviewed and refined manually.
"""

import os, sys, re, json, argparse
from collections import Counter, defaultdict

CANDIDATE_LIMIT = 100

def collect_py_files(path):
    if os.path.isfile(path) and path.endswith(".py"):
        return [path]
    res = []
    for root, dirs, files in os.walk(path):
        for f in files:
            if f.endswith(".py"):
                res.append(os.path.join(root, f))
    return res

def find_patterns_in_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        text = fh.read()
    findings = []
    # heuristics
    if re.search(r"\\bopen\\s*\\(", text):
        findings.append(("open_without_with", r"\\bopen\\s*\\([^\\)]*\\)\\s*\\n"))
    if re.search(r"\\bprint\\s*\\(", text):
        findings.append(("print_debug", r"\\bprint\\s*\\("))
    if re.search(r"#\\s*(TODO|FIXME)", text):
        findings.append(("todo_fixme", r"#\\s*(TODO|FIXME)"))
    if re.search(r"os\\.environ\\[", text):
        findings.append(("os_environ", r"os\\.environ\\["))
    if re.search(r"\\binput\\s*\\(", text):
        findings.append(("input_call", r"\\binput\\s*\\("))
    if re.search(r"try\\s*:\\s*\\n(?!\\s*(except|finally))", text):
        findings.append(("try_no_except", r"try\\s*:\\s*\\n(?!\\s*(except|finally))"))
    if re.search(r"for\\s+\\w+\\s+in\\s+[\\w\\.\\[\\]'\\\"]+:\\s*\\n\\s*(pass|#)", text):
        findings.append(("empty_for", r"for\\s+\\w+\\s+in\\s+[\\w\\.\\[\\]'\\\"]+:\\s*\\n\\s*(pass|#)"))
    # look for repeated variable reassign pattern: var = ... then var = ... within same file
    vars = re.findall(r"\\b(\\w+)\\s*=", text)
    dup = [v for v,count in Counter(vars).items() if count>3]
    for v in dup:
        findings.append(("reassign_var", r"\\b"+re.escape(v)+r"\\s*="))
    return findings

def discover(path, min_count=1):
    files = collect_py_files(path)
    counter = Counter()
    patterns = defaultdict(int)
    examples = defaultdict(list)
    for f in files:
        found = find_patterns_in_file(f)
        for key, pat in found:
            patterns[pat] += 1
            counter[key] += 1
            if len(examples[pat])<5:
                examples[pat].append(f)
    # build suggestions sorted by frequency
    suggestions = []
    for pat, count in sorted(patterns.items(), key=lambda x: -x[1]):
        if count < min_count:
            continue
        suggestions.append({
            "id": f"DISC_{abs(hash(pat))%10000}",
            "type": "Suggestion",
            "message": f"Candidate pattern detected in {count} files. Review before enabling.",
            "pattern": pat,
            "severity": "low",
            "examples": examples.get(pat,[]),
            "count": count
        })
        if len(suggestions)>=CANDIDATE_LIMIT:
            break
    return suggestions

def main():
    p = argparse.ArgumentParser()
    p.add_argument("path", help="file or directory to analyze for rule discovery")
    p.add_argument("--out", default="candidates.json", help="output file for suggestions")
    p.add_argument("--min-count", type=int, default=1, help="minimum number of files a pattern must appear in")
    args = p.parse_args()
    s = discover(args.path, min_count=args.min_count)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(s, fh, indent=2, ensure_ascii=False)
    print(f"Saved {len(s)} suggestions to {args.out}")

if __name__ == '__main__':
    main()
