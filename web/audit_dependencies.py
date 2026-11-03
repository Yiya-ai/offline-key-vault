"""Opt-in public advisory lookup: sends only public package names and versions.

No repository contents, keys, passwords, paths or environment values are sent.
Any advisory or unavailable/malformed response blocks release (no ignore list).
"""
import argparse
import json
from pathlib import Path
import re
import urllib.request

WEB = Path(__file__).resolve().parent


def packages():
    locked = json.loads((WEB / 'dependencies.lock.json').read_text(encoding='utf-8'))
    result = []
    for item in locked['files']:
        match = re.fullmatch(r'[A-Za-z0-9_]+-([0-9]+(?:\.[0-9]+)+)(?:-.+\.whl|\.tar\.gz)', item['file'])
        if not match:
            raise ValueError('Unsupported locked package filename')
        result.append({'package': {'name': item['name'], 'ecosystem': 'PyPI'}, 'version': match[1]})
    return result


def findings(queries, response):
    results = response.get('results')
    if not isinstance(results, list) or len(results) != len(queries):
        raise ValueError('Incomplete advisory response')
    rows = []
    for query, result in zip(queries, results):
        if not isinstance(result, dict):
            raise ValueError('Malformed advisory result')
        vulns = result.get('vulns', [])
        if not isinstance(vulns, list) or result.get('next_page_token'):
            raise ValueError('Incomplete advisory result')
        ids = []
        for vuln in vulns:
            if not isinstance(vuln, dict) or not isinstance(vuln.get('id'), str):
                raise ValueError('Malformed advisory identifier')
            ids.append(vuln['id'])
        if ids:
            rows.append({'package': query['package']['name'], 'version': query['version'], 'advisories': sorted(ids)})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--online', action='store_true', help='Query OSV using public package names and versions only')
    args = parser.parse_args()
    if not args.online:
        parser.error('Use --online explicitly; this is a development/release check only')
    try:
        queries = packages()
        request = urllib.request.Request('https://api.osv.dev/v1/querybatch',
            data=json.dumps({'queries': queries}).encode('utf-8'), headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError('Oversized advisory response')
        rows = findings(queries, json.loads(raw))
        print(json.dumps({'ok': not rows, 'packages': len(queries), 'findings': rows}))
        return 1 if rows else 0
    except Exception:
        print(json.dumps({'ok': False, 'error': 'Advisory check unavailable or invalid; release blocked'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
