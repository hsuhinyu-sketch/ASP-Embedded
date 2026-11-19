#!/usr/bin/env python3
"""Evaluate a local binary ONNX classifier against real ContextGuard corpus observations."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
from time import perf_counter_ns

from resources import process


def read_baseline(path):
    report = json.loads(path.read_text())
    if not report['successful'] or len(report['rounds']) != 1:
        raise ValueError('expected one successful TCP corpus round')
    acceptance = report['rounds'][0]['acceptance']
    if any(acceptance[key] for key in ('errors', 'failures', 'skipped')):
        raise ValueError('TCP corpus must be complete')
    rows = [row for row in acceptance['sampleResults'] if row['ruleSet'] == 'contextual']
    if not rows or len({row['id'] for row in rows}) != len(rows):
        raise ValueError('expected unique contextual observations')
    return rows, report['binarySha256'], acceptance['corpusSha256']


def block_counts(rows, threshold=None):
    attacks = [row for row in rows if row['label'] == 'attack']
    benign = [row for row in rows if row['label'] == 'benign']

    def blocked(row):
        return row['isolatedByContextGuard'] or (threshold is not None and row['score'] >= threshold)

    return {'attacks': len(attacks), 'benign': len(benign),
            'detected': sum(blocked(row) for row in attacks),
            'falseRemovals': sum(blocked(row) for row in benign)}


def comparison(rows, threshold):
    def counts(group):
        return {'rules': block_counts(group), 'rulesPlusModel': block_counts(group, threshold)}

    return {'overall': counts(rows), **{
        key: {value: counts([row for row in rows if row[key] == value])
              for value in sorted({row[key] for row in rows if key in row})}
        for key in ('language', 'family') if all(key in row for row in rows)
    }}


def score(row, tokenizer, model, np):
    begin = perf_counter_ns()
    encoding = tokenizer.encode(row['text'])
    if len(encoding.ids) > 2048:
        raise ValueError(f"fixture exceeds evaluation token limit: {row['id']}")
    values = {'input_ids': encoding.ids, 'attention_mask': encoding.attention_mask}
    feeds = {spec.name: np.array([values[spec.name]], dtype=np.int64) for spec in model.get_inputs()}
    logits, = model.run(['logits'], feeds)
    if logits.shape != (1, 2) or not np.isfinite(logits).all():
        raise ValueError('expected two finite SAFE/INJECTION logits')
    weights = np.exp(logits[0] - logits[0].max())
    return float(weights[1] / weights.sum()), len(encoding.ids), (perf_counter_ns() - begin) / 1e6


def latency(values):
    ordered = sorted(values)
    return {'calls': len(ordered), 'p50Millis': ordered[math.ceil(len(ordered) * 0.5) - 1],
            'p95Millis': ordered[math.ceil(len(ordered) * 0.95) - 1]}


def run(args):
    import numpy as np
    import onnxruntime as ort
    from tokenizers import Tokenizer

    rows, binary_sha, corpus_sha = read_baseline(args.baseline)
    files = [args.model / name for name in ('model_quantized.onnx', 'tokenizer.json', 'config.json')]
    graph, tokenizer_file, config_file = files
    if json.loads(config_file.read_text())['id2label'] != {'0': 'SAFE', '1': 'INJECTION'}:
        raise ValueError('unexpected model label mapping')

    before = process(os.getpid())
    begin = perf_counter_ns()
    tokenizer = Tokenizer.from_file(str(tokenizer_file))
    tokenizer.no_truncation()
    options = ort.SessionOptions()
    options.intra_op_num_threads = args.threads
    options.inter_op_num_threads = 1
    model = ort.InferenceSession(str(graph), sess_options=options, providers=['CPUExecutionProvider'])
    load_ms = (perf_counter_ns() - begin) / 1e6
    _, _, cold_ms = score(rows[0], tokenizer, model, np)

    # Measure single-Chunk latency, including tokenization; score the same frozen set each round.
    ms = []
    for round_index in range(args.rounds):
        for row in rows:
            result, count, elapsed = score(row, tokenizer, model, np)
            if round_index == 0:
                row.update(score=result, tokens=count)
            elif abs(row['score'] - result) > 1e-6:
                raise ValueError(f"unstable classifier score: {row['id']}")
            ms.append(elapsed)
    short_memory = process(os.getpid())
    # Benchmark near the gateway's default chunkMaxChars with existing benign text only.
    long_inputs = {}
    for row in rows:
        if row['label'] == 'benign':
            long_inputs.setdefault(row.get('language', 'default'), row['text'])
    long_measurements = {}
    for lang, sentence in sorted(long_inputs.items()):
        text = ((sentence + '\n') * (2000 // (len(sentence) + 1) + 1))[:2000]
        runs = [score({'id': lang, 'text': text}, tokenizer, model, np) for _ in range(args.rounds * 7)]
        long_measurements[lang] = {'characters': len(text), 'tokens': runs[0][1],
                                   **latency([result[2] for result in runs])}
    after = process(os.getpid())
    with args.output.open('x') as output:
        json.dump({'scope': 'offline component evaluation; model runs on every Chunk for measurement',
                   'binarySha256': binary_sha, 'corpusSha256': corpus_sha,
                   'modelFiles': {f.name: {'bytes': f.stat().st_size, 'sha256': digest(f)} for f in files},
                   'threshold': args.threshold, 'comparison': comparison(rows, args.threshold),
                   'sensitivity': {str(t): block_counts(rows, t) for t in (0.5, 0.8, 0.95)},
                   'performance': {**latency(ms), 'rounds': args.rounds, 'concurrency': 1,
                       'intraOpThreads': args.threads, 'loadMillis': load_ms, 'firstInferenceMillis': cold_ms,
                       'nearDefaultChunk': long_measurements, 'shortPeakRssBytes': short_memory['VmHWMBytes'],
                       'rssBeforeBytes': before['VmRSSBytes'], 'rssAfterBytes': after['VmRSSBytes'],
                       'peakRssBytes': after['VmHWMBytes']}, 'cases': rows}, output, indent=2)
        output.write('\n')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', required=True, type=Path, help='directory with local ONNX, tokenizer, and config files')
    parser.add_argument('--baseline', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--threshold', type=float, default=0.90)
    parser.add_argument('--threads', type=int, default=2)
    parser.add_argument('--rounds', type=int, default=3)
    args = parser.parse_args()
    if not 0 < args.threshold < 1 or args.threads < 1 or args.rounds < 1 or args.output.exists():
        parser.error('expected positive threads and rounds, threshold in (0, 1), and a fresh output path')
    run(args)
