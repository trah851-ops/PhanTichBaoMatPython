# cli.py
import argparse, os, json
from analyzer.core import analyze_file
from reporter.html_report import build_html_report

def collect_python_files(path):
    if os.path.isfile(path) and path.endswith('.py'):
        return [path]
    result = []
    for root, dirs, files in os.walk(path):
        for f in files:
            if f.endswith('.py'):
                result.append(os.path.join(root, f))
    return result

def scan(paths, rules=None):
    all_issues = []
    for p in paths:
        files = collect_python_files(p)
        for f in files:
            res = analyze_file(f, rules_path=rules)
            for it in res['issues']:
                it['file'] = f
                all_issues.append(it)
    summary = {'total_issues': len(all_issues)}
    return {'issues': all_issues, 'summary': summary}

def main():
    p = argparse.ArgumentParser()
    p.add_argument('paths', nargs='+')
    p.add_argument('--rules', default=None)
    p.add_argument('--out-json', default=None)
    p.add_argument('--out-html', default=None)
    args = p.parse_args()
    res = scan(args.paths, rules=args.rules)
    if args.out_json:
        with open(args.out_json, 'w', encoding='utf-8') as fh:
            json.dump(res, fh, indent=2, ensure_ascii=False)
    if args.out_html:
        html = build_html_report(res)
        with open(args.out_html, 'w', encoding='utf-8') as fh:
            fh.write(html)
    print('Scan finished. Issues:', res['summary']['total_issues'])

if __name__ == '__main__':
    main()
