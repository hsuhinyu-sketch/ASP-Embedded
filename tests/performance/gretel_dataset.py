"""Normalize the pinned Gretel test split and score exact UTF-8 byte spans.

Gretel supplies entity strings, not offsets. Every exact occurrence is reconstructed;
missing annotations are counted separately. This is an annotation-relative evaluation.
"""
import argparse
import ast
from collections import Counter
import hashlib
import json
import os
from pathlib import Path

DATASET = 'gretelai/gretel-pii-masking-en-v1'
REVISION = 'e06eb1499ca8d54470f085021cd8e54f9efac7fd'
PARQUET_SHA256 = 'c89a6bffa838edb0f2fc6686bf35da4930944519ac97308b0b6e32298594b5b1'
ENTITY_MAP = {'email': 'EMAIL_ADDRESS', 'phone_number': 'PHONE_NUMBER',
              'ipv4': 'IP_ADDRESS', 'ipv6': 'IP_ADDRESS'}
from pii_dataset import SUPPORTED, counts, covered, load_jsonl, rates, score, write_jsonl


def normalize(row):
    text = row['text']
    entities = row['entities']
    if isinstance(entities, str):
        entities = ast.literal_eval(entities)
    spans, missing = set(), Counter()
    for entity in entities:
        value, types = entity['entity'], entity['types']
        if not value or not isinstance(types, list) or not types:
            raise ValueError('invalid source entity')
        starts, cursor = [], 0
        while (start := text.find(value, cursor)) >= 0:
            starts.append(start)
            cursor = start + len(value)
        for kind in types:
            canonical = ENTITY_MAP.get(kind, 'source:' + kind)
            if not starts:
                missing[kind] += 1
            for start in starts:
                begin = len(text[:start].encode('utf-8'))
                spans.add((begin, begin + len(value.encode('utf-8')), canonical))
    return {'id': row['uid'], 'text': text, 'domain': row['domain'],
            'gold': [{'start': a, 'end': b, 'entityType': kind} for a, b, kind in sorted(spans)],
            'missingAnnotations': dict(missing)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parquet', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    import pyarrow
    import pyarrow.parquet as parquet
    if hashlib.sha256(args.parquet.read_bytes()).hexdigest() != PARQUET_SHA256:
        raise ValueError('Parquet differs from official pinned test file')
    rows = [normalize(row) for row in parquet.read_table(args.parquet).to_pylist()]
    if len(rows) != 5000 or len({row['id'] for row in rows}) != len(rows):
        raise ValueError('unexpected test split size or duplicate IDs')
    os.umask(0o077)
    args.out.mkdir(parents=True, exist_ok=False)
    write_jsonl(args.out / 'test.jsonl', rows)
    value = {'dataset': DATASET, 'revision': REVISION, 'split': 'test', 'rows': len(rows),
             'license': 'apache-2.0', 'parquetSha256': PARQUET_SHA256,
             'normalizedSha256': hashlib.sha256((args.out / 'test.jsonl').read_bytes()).hexdigest(),
             'pyarrowVersion': pyarrow.__version__, 'entityMap': ENTITY_MAP,
             'annotationMethod': 'literal-occurrence'}
    (args.out / 'manifest.json').write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps(value))


if __name__ == '__main__':
    main()
