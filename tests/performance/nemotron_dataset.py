"""Prepare a fixed, balanced Nemotron-PII test sample using verified source spans."""
import argparse
import ast
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import random

from pii_dataset import write_jsonl

DATASET = 'nvidia/Nemotron-PII'
REVISION = 'b70ffaf5ff39e079776134c5bf4381f00a9fd1ed'
PARQUET_SHA256 = '1a4b0512ecb5370f0992d29d0f9c07351e6de13f0d7ea33bb18cecb984780247'
ENTITY_MAP = {'email': 'EMAIL_ADDRESS', 'phone_number': 'PHONE_NUMBER',
              'ipv4': 'IP_ADDRESS', 'ipv6': 'IP_ADDRESS', 'ip_address': 'IP_ADDRESS'}
SEED = 20261104


def normalize(row):
    text = row['text']
    source = row['spans']
    if isinstance(source, str):
        source = ast.literal_eval(source)
    spans, normalizations = set(), Counter()
    for span in source:
        start, end, label = span['start'], span['end'], span['label']
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(text):
            raise ValueError('invalid-character-range')
        quoted = span['text']
        if type(quoted) is int:
            quoted = str(quoted)
            normalizations['numeric-text'] += 1
        if not isinstance(quoted, str):
            raise ValueError('invalid-span-text-type')
        if text[start:end] != quoted and text[start:end].casefold() == quoted.casefold():
            normalizations['case-only'] += 1
        elif text[start:end] != quoted:
            raise ValueError('span-text-mismatch')
        begin = len(text[:start].encode('utf-8'))
        stop = begin + len(text[start:end].encode('utf-8'))
        spans.add((begin, stop, ENTITY_MAP.get(label, 'source:' + label)))
    return {'id': row['locale'] + ':' + row['uid'], 'sourceUid': row['uid'],
            'text': text, 'domain': row['domain'], 'locale': row['locale'],
            'documentFormat': row['document_format'],
            'gold': [{'start': a, 'end': b, 'entityType': label} for a, b, label in sorted(spans)],
            'missingAnnotations': {}, 'annotationNormalizations': dict(normalizations)}


def reservoir(rows, per_stratum, seed=SEED):
    """Bound memory while sampling each locale/format group without replacement."""
    rng = random.Random(seed)
    groups, populations = defaultdict(list), Counter()
    for row in rows:
        key = (row['locale'], row['document_format'])
        populations[key] += 1
        sample = groups[key]
        if len(sample) < per_stratum:
            sample.append(row)
        elif (index := rng.randrange(populations[key])) < per_stratum:
            sample[index] = row
    selected = [row for key in sorted(groups) for row in groups[key]]
    rng.shuffle(selected)
    return selected, populations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parquet', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--per-stratum', type=int, default=2500)
    args = parser.parse_args()
    if not 1 <= args.per_stratum <= 25000:
        parser.error('--per-stratum must be between 1 and 25000')
    import pyarrow
    import pyarrow.parquet as parquet
    if hashlib.sha256(args.parquet.read_bytes()).hexdigest() != PARQUET_SHA256:
        raise ValueError('Parquet differs from pinned NVIDIA test file')
    source = parquet.ParquetFile(args.parquet)
    def rows():
        for batch in source.iter_batches(batch_size=1024):
            yield from batch.to_pylist()
    selected, populations = reservoir(rows(), args.per_stratum)
    if len({(row['locale'], row['uid']) for row in selected}) != len(selected):
        raise ValueError('duplicate selected locale/source IDs')
    valid, excluded = [], []
    for row in selected:
        try:
            valid.append(normalize(row))
        except (ValueError, KeyError, TypeError) as error:
            # No automatic offset repair, partial-label deletion or replacement sampling.
            excluded.append({'id': row['locale'] + ':' + row['uid'], 'locale': row['locale'],
                'documentFormat': row['document_format'], 'reason': type(error).__name__,
                'code': str(error) if type(error) is ValueError else 'invalid-span-schema'})
    os.umask(0o077)
    args.out.mkdir(parents=True, exist_ok=False)
    write_jsonl(args.out / 'test.jsonl', valid)
    (args.out / 'excluded.json').write_text(json.dumps(excluded, indent=2) + '\n')
    (args.out / 'selected-ids.json').write_text(json.dumps([r['locale'] + ':' + r['uid'] for r in selected]) + '\n')
    manifest = {'dataset': DATASET, 'revision': REVISION, 'split': 'test', 'license': 'cc-by-4.0',
        'sourceRows': source.metadata.num_rows, 'sourceStrata': {'/'.join(k): v for k, v in populations.items()},
        'selectedRows': len(selected), 'rows': len(valid), 'excludedDocuments': len(excluded),
        'excludedReasons': dict(Counter(r['code'] for r in excluded)), 'seed': SEED,
        'sampling': 'reservoir without replacement per locale/document_format; no resampling excluded documents',
        'perStratum': args.per_stratum, 'parquetSha256': PARQUET_SHA256,
        'normalizedSha256': hashlib.sha256((args.out / 'test.jsonl').read_bytes()).hexdigest(),
        'pyarrowVersion': pyarrow.__version__, 'entityMap': ENTITY_MAP,
        'annotationMethod': 'official-character-spans-verified-against-text-converted-to-UTF8',
        'spanTextValidation': 'integer text stringification and casefold equality allowed; no offset changes',
        'annotationNormalizations': dict(sum((Counter(r['annotationNormalizations']) for r in valid), Counter())),
        'validStrata': dict(Counter(r['locale'] + '/' + r['documentFormat'] for r in valid))}
    (args.out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest))


if __name__ == '__main__':
    main()
