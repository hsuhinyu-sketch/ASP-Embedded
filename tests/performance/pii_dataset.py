"""Shared exact-span scoring and JSONL I/O for offline PII dataset evaluations."""
from collections import Counter
import json
from pathlib import Path

SUPPORTED = frozenset(('EMAIL_ADDRESS', 'PHONE_NUMBER', 'IP_ADDRESS'))


def span_set(findings):
    return {(v['start'], v['end'], v['entityType']) for v in findings}


def counts(gold, predicted):
    return {'tp': len(gold & predicted), 'fp': len(predicted - gold), 'fn': len(gold - predicted)}


def rates(values):
    tp, fp, fn = (values[k] for k in ('tp', 'fp', 'fn'))
    return {**values, 'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / (tp + fn) if tp + fn else None,
            'f1': 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None}


def covered(span, predicted):
    """Whether the union of mutation spans covers every byte of a source entity."""
    cursor, end = span[:2]
    for begin, stop, _ in sorted(predicted):
        if begin > cursor:
            break
        cursor = max(cursor, stop)
        if cursor >= end:
            return True
    return False


def score(records, outcomes, annotation_method="literal-occurrence"):
    if len(records) != len(outcomes):
        raise ValueError('missing evaluator records')
    per_type = {kind: Counter(tp=0, fp=0, fn=0) for kind in sorted(SUPPORTED)}
    inventory, missing, errors = Counter(), Counter(), Counter()
    total_gold = supported_gold = mask_covered = exact_documents = 0
    details = []
    for row, output in zip(records, outcomes):
        if row['id'] != output['id']:
            raise ValueError('evaluator record order mismatch')
        all_gold = span_set(row['gold'])
        gold = {s for s in all_gold if s[2] in SUPPORTED}
        predicted = span_set(output.get('findings', []))
        if 'error' in output:
            errors[output['error']] += 1
        if not {s[2] for s in predicted} <= SUPPORTED:
            raise ValueError('unexpected detector entity type')
        for kind, values in per_type.items():
            values.update(counts({s for s in gold if s[2] == kind}, {s for s in predicted if s[2] == kind}))
        inventory.update(s[2] for s in all_gold)
        missing.update(row['missingAnnotations'])
        total_gold += len(all_gold)
        supported_gold += len(gold)
        mask_covered += sum(covered(s, predicted) for s in gold)
        exact_documents += gold == predicted and 'error' not in output
        details.append({'id': row['id'], **counts(gold, predicted), 'error': output.get('error')})
    total = Counter(tp=0, fp=0, fn=0)
    for value in per_type.values():
        total.update(value)
    return {'documents': len(records), 'exactDocuments': exact_documents,
            'supported': rates(total), 'perType': {k: rates(v) for k, v in per_type.items()},
            'allAnnotatedSpans': total_gold, 'supportedAnnotatedSpans': supported_gold,
            'supportedSpanCoverage': supported_gold / total_gold if total_gold else None,
            'supportedMaskCoverage': mask_covered / supported_gold if supported_gold else None,
            'annotationTypeInventory': dict(inventory), 'annotationsAbsentFromText': dict(missing),
            'engineErrors': dict(errors), 'records': details,
            'annotationMethod': annotation_method,
            'limitations': 'exact typed UTF-8 span scoring; unsupported labels excluded only from supported scores; no independently adjudicated precision; annotation provenance and exclusions in input manifest'}


def load_jsonl(path):
    with Path(path).open() as source:
        return [json.loads(line) for line in source]


def write_jsonl(path, rows):
    with Path(path).open('x') as output:
        for row in rows:
            output.write(json.dumps(row, ensure_ascii=False) + '\n')
