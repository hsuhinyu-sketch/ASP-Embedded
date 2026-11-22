#!/usr/bin/env python3
"""Measure an authorized Android LLM Release with local, content-validated workloads."""

import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

from build_release import digest
from http_workload import Client, encode, quantiles, valid
from resources import proc_stat, window
from run_baseline import Gateway, HERE, save, stop, wait_file
from stream_workload import CHUNK_BYTES, GAP_SECONDS, INITIAL_SECONDS, load

from run_android_audit import Device, audit_status, gateway_process, request, require


OUTPUT_BYTES = 8192


def conditions(device):
    raw = device.shell('for zone in /sys/class/thermal/thermal_zone*; do '
                       'if test -r "$zone/type" && test -r "$zone/temp"; then '
                       'echo "$(cat "$zone/type") $(cat "$zone/temp")"; fi; done').stdout
    temperatures = {name: int(value) for name, value in re.findall(r'^(\S+)\s+(-?\d+)$', raw, re.M)}
    battery = device.shell('dumpsys battery', check=False).stdout
    return {'thermalZoneRaw': temperatures, 'battery': dict(
        (key.strip(), value.strip()) for key, _, value in
        (line.partition(':') for line in battery.splitlines())
        if key.strip() in ('USB powered', 'level', 'status', 'temperature'))}


@contextmanager
def sample_device(device, pid, ticks, file):
    rows, errors = [], []
    ended = threading.Event()
    root = f'/proc/{pid}'

    def collect():
        next_pss = 0
        with file.open('x') as output:
            while not ended.is_set():
                now = time.monotonic_ns()
                try:
                    command = f'cat {root}/stat && grep -E "^(VmRSS|VmHWM|VmSwap|Threads):" {root}/status'
                    if now >= next_pss:
                        command += (f"; if test -r {root}/smaps; then awk '/^Pss:/ {{sum += $2; n++}} "
                                    f'END {{if (n) print "Pss:",sum}}\' {root}/smaps; fi')
                        next_pss = now + 5_000_000_000
                    result = device.shell(command)
                    lines = result.stdout.splitlines()
                    values = proc_stat(lines[0], ticks)
                    fields = dict((key, value.split()[0]) for key, _, value in
                                  (line.partition(':') for line in lines[1:]))
                    for key in ('VmRSS', 'VmHWM', 'VmSwap'):
                        if key in fields:
                            values[key + 'Bytes'] = int(fields[key]) * 1024
                    values['threads'] = int(fields['Threads'])
                    if 'Pss' in fields:
                        values['pssBytes'] = int(fields['Pss']) * 1024
                    row = {'monotonicNs': now, 'wallNs': time.time_ns(), 'processes': {'gateway': values}}
                    rows.append(row)
                    output.write(json.dumps(row) + '\n')
                    output.flush()
                except (OSError, ValueError, IndexError, KeyError, subprocess.SubprocessError) as error:
                    errors.append(str(error))
                ended.wait(max(0, 1 - (time.monotonic_ns() - now) / 1e9))

    thread = threading.Thread(target=collect, daemon=True)
    thread.start()
    try:
        yield rows
    finally:
        ended.set()
        thread.join(35)
        require(not thread.is_alive(), 'ADB process sampler did not stop')
        require(rows and not errors, f'ADB process sampling failed: {errors[:3]}')


async def preflight(port, headers):
    client = Client(port)
    data = encode({'model': 'local', 'messages': [{'role': 'user', 'content': 'benchmark question'}]})
    try:
        status, reply_headers, output = await client.request('/v1/chat/completions', data, headers)
        require(status == 200 and valid('llm', reply_headers, output), f'preflight returned HTTP {status}: {output[:200]!r}')
    finally:
        await client.close()


def workload(out, name, port, headers, stream, concurrency, warmup, seconds, rows=None):
    path = out / name
    path.mkdir()
    args = SimpleNamespace(port=port, headers=headers, stream=stream, output_bytes=OUTPUT_BYTES,
                           concurrency=concurrency, warmup=warmup, seconds=seconds,
                           samples=path / 'requests.csv', report=path / 'load.json')
    print(f'{name}: concurrency={concurrency}, {seconds}s', flush=True)
    status = asyncio.run(load(args))
    reading = json.loads(args.report.read_text())
    if rows is not None:
        reading['gateway'] = window(rows, 'gateway', reading['measuredStartNs'], reading['finishedNs'])
    save(path / 'result.json', reading)
    require(status == 0 and reading['completed'] > 0, f'workload failed; see {args.report}')
    return reading


def metrics_snapshot(port, path):
    status, _, body = request(port, 'GET', '/metrics')
    require(status == 200, f'metrics endpoint returned HTTP {status}')
    path.write_bytes(body)
    return body


@contextmanager
def loopback_relay(device, directory, out, binary, listen, destination):
    remote = f'{directory}/loopback-relay'
    pid_file = f'{directory}/relay.pid'
    device.run('push', str(binary.resolve()), remote)
    device.shell(f'chmod 700 {remote}')
    command = f'echo "$$" > {pid_file} && exec {remote} {listen} {destination}'
    log = out / 'relay.log'
    with log.open('xb') as output:
        process = subprocess.Popen(device.command + ['shell', '-T', command], stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                require(process.poll() is None, f'ADB relay exited; see {log}')
                if log.read_bytes() == b'ready\n':
                    break
                time.sleep(.025)
            else:
                raise RuntimeError(f'ADB relay did not start; see {log}')
            yield
        finally:
            if process.poll() is None:
                try:
                    device.shell(f'kill -TERM "$(cat {pid_file})"')
                    process.wait(timeout=5)
                finally:
                    if process.poll() is None:
                        stop(process)


def profile(device, directory, pid, out, port, headers):
    data = f'{directory}/perf.data'
    with ThreadPoolExecutor(max_workers=1) as pool:
        recording = pool.submit(device.shell, f'simpleperf record -e task-clock:u -f 99 '
                                f'-p {pid} --duration 10 --call-graph dwarf -o {data}', check=False)
        workload(out, 'profile-http-c8', port, headers, False, 8, 0, 12)
        result = recording.result()
    (out / 'simpleperf-record.log').write_text(result.stdout + result.stderr)
    if result.returncode:
        return {'successful': False, 'recordExitCode': result.returncode}
    device.run('pull', data, str(out / 'perf.data'))
    result = device.shell(f'simpleperf report -i {data} --sort dso,symbol', check=False)
    (out / 'simpleperf-report.txt').write_text(result.stdout + result.stderr)
    return {'successful': result.returncode == 0, 'reportExitCode': result.returncode}


def run(args, out, report):
    device = Device(args.adb, args.serial)
    with ExitStack() as cleanup:
        directory = device.shell('umask 077 && mktemp -d /data/local/tmp/asp-embedded-perf.XXXXXX').stdout.strip()
        require(re.fullmatch(r'/data/local/tmp/asp-embedded-perf\.[a-zA-Z0-9]+', directory),
                'ADB did not return a dedicated performance directory')
        cleanup.callback(device.shell, shlex.join(['rm', '-rf', directory]))
        remote_bin, remote_config = f'{directory}/ai-security-platform', f'{directory}/gateway.json'
        device.run('push', str(args.binary), remote_bin)
        device.shell(f'chmod 700 {remote_bin}')
        sync_library = f'{directory}/audit-sync.so'
        if args.audit_sync_probe:
            device.run('push', str(args.audit_sync_probe.resolve()), sync_library)
        expected = json.loads(args.acceptance.read_text())
        actual_digest = digest(args.binary)
        require(expected['successful'] and expected['binarySha256'] == actual_digest,
                'Release binary must match the supplied successful security report')
        require(device.shell(f'toybox sha256sum {remote_bin}').stdout.split()[0] == actual_digest,
                'device binary digest differs from local binary')
        version = json.loads(device.shell(f'{remote_bin} --version').stdout)
        require(version['build_target'] == 'aarch64-linux-android' and version['build_profile'] == 'release',
                f'incorrect Android release build: {version}')
        ticks = int(device.shell('getconf CLK_TCK').stdout)
        report.update(binarySha256=actual_digest, version=version, acceptance=str(args.acceptance),
                      device=device.shell('getprop ro.product.model; getprop ro.build.version.sdk; uname -rm; getenforce').stdout.splitlines(),
                      cpuTicksPerSecond=ticks, conditionsBefore=conditions(device),
                      latencyScope='host client via ADB forward; upstream fixture via ADB reverse',
                      sampling={'rssAndCpuSeconds': 1, 'pssSeconds': 5, 'pssSource': '/proc/PID/smaps'},
                      payload={'outputContentBytes': OUTPUT_BYTES, 'sseChunkContentBytes': CHUNK_BYTES,
                               'upstreamInitialDelayMs': INITIAL_SECONDS * 1000, 'upstreamChunkGapMs': GAP_SECONDS * 1000})

        upstream_ready, counters = out / 'upstream.ready.json', out / 'upstream.counters.json'
        upstream_log = cleanup.enter_context((out / 'upstream.log').open('xb'))
        upstream = subprocess.Popen([sys.executable, str(HERE / 'stream_workload.py'), 'serve',
                                     '--ready', str(upstream_ready), '--counters', str(counters),
                                     '--output-bytes', str(OUTPUT_BYTES)], stdout=upstream_log,
                                    stderr=subprocess.STDOUT, start_new_session=True)
        cleanup.callback(stop, upstream)
        upstream_port = wait_file(upstream_ready, upstream)['port']
        endpoint = f'tcp:{upstream_port}'
        device.run('reverse', '--no-rebind', endpoint, endpoint)
        cleanup.callback(device.run, 'reverse', '--remove', endpoint)
        fixture = Gateway(str(args.binary), out, upstream_port, llm_only=True)
        fixture.role_ports.close()
        cleanup.callback(fixture.signer.close)
        llm = device.forward(fixture.model_port, cleanup)
        admin = device.forward(fixture.role_ports.ports['admin'], cleanup)
        ready = device.forward(fixture.role_ports.ports['readiness'], cleanup)
        stats = device.forward(fixture.role_ports.ports['stats'], cleanup) if args.collect_stages else None
        config = json.loads(fixture.config.read_text())
        config['config'].update(bindAddress='127.0.0.1', management={'mode': 'diagnostic'},
                                dns={'lookupFamily': 'V4Only'})
        if args.worker_threads is not None:
            config['config']['workerThreads'] = args.worker_threads
        system = config['aiSystems'][0]
        host = f'localhost:{upstream_port}'
        system['llm']['models'][0]['params']['baseUrl'] = f'http://{host}/v1'
        system['security'].update(requiredAudit={'actionTypes': ['modelInvoke']},
                                  requiredIdentity={'user': True, 'tenant': True, 'agent': False},
                                  dataEgress={'classification': 'internal', 'modelDestinations': [host]})
        report['security'] = {'mode': 'enforce', 'jwt': 'strict Ed25519', 'requiredAudit': True,
                              'localExplicitEgress': True, 'logLevel': 'warn', 'auditMaximumBytes': 536870912}

        @contextmanager
        def running(label):
            section = out / label
            section.mkdir()
            audit_dir = f'{directory}/audit-{label}'
            device.shell(f'umask 077 && mkdir {audit_dir}')
            config['config']['securityAudit'] = {
                'directory': audit_dir, 'maxSegmentBytes': 67108864, 'maxSegments': 8, 'retentionSeconds': 604800,
            }
            config_path = section / 'gateway.json'
            save(config_path, config)
            device.run('push', str(config_path), remote_config)
            headers = section / 'headers.json'
            save(headers, {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + fixture.token(ttl_seconds=1800)})
            environment = ['env', 'RUST_LOG=warn']
            if args.audit_sync_probe:
                environment.extend([f'LD_PRELOAD={sync_library}', f'AISP_SYNC_AUDIT_DIR={audit_dir}',
                                    f'AISP_SYNC_TRACE={directory}/{label}.sync.bin'])
            cmd = shlex.join(environment + [remote_bin, '--file', remote_config])
            start = time.monotonic_ns()
            log = section / 'gateway.log'
            with gateway_process(device, cmd, directory, log, admin, readiness_port=ready):
                startup_ms = (time.monotonic_ns() - start) / 1e6
                pid = int(device.shell(f'cat {directory}/gateway.pid').stdout)
                report['startupMs'].append({'session': label, 'ms': startup_ms})
                with sample_device(device, pid, ticks, section / 'resources.jsonl') as rows:
                    begin = time.monotonic_ns()
                    time.sleep(args.idle)
                    idle = window(rows, 'gateway', begin, time.monotonic_ns())
                    asyncio.run(preflight(llm, json.loads(headers.read_text())))
                    yield section, headers, rows, pid, idle
                    require(audit_status(admin)['persistenceHealthy'], 'Required Audit unhealthy at end of session')

        direct_headers = out / 'direct-headers.json'
        save(direct_headers, {'Content-Type': 'application/json'})
        modes = (False,) if args.http_only else (False, True)
        lines = [(stream, concurrency) for concurrency in args.concurrency for stream in modes]
        for stream, concurrency in lines:
            name = f'direct-{"sse" if stream else "http"}-c{concurrency}'
            reading = workload(out, name, upstream_port, direct_headers, stream, concurrency, args.warmup, args.seconds)
            report['direct'][name] = reading
            save(out / 'report.json', report)
        if args.relay:
            with ExitStack() as relay_cleanup:
                relay_port = device.forward(fixture.port, relay_cleanup)
                with loopback_relay(device, directory, out, args.relay, fixture.port, upstream_port):
                    report['adbControl'] = {}
                    for stream, concurrency in lines:
                        name = f'adb-{"sse" if stream else "http"}-c{concurrency}'
                        report['adbControl'][name] = workload(out, name, relay_port, direct_headers, stream,
                                                              concurrency, args.warmup, args.seconds)
                        save(out / 'report.json', report)
        for round_number in range(1, args.rounds + 1):
            label = f'round-{round_number}'
            remote_trace = f'{directory}/{label}.sync.bin' if args.audit_sync_probe else None
            with running(label) as (section, headers, rows, _, idle):
                record = {'idle': idle, 'cases': {}, 'conditionsBefore': conditions(device)}
                report['rounds'][label] = record
                for stream, concurrency in (lines if round_number % 2 else reversed(lines)):
                    name = f'{"sse" if stream else "http"}-c{concurrency}'
                    if stats is not None:
                        metrics_snapshot(stats, section / f'{name}.before.prom')
                    if remote_trace:
                        start = int(device.shell(f'toybox stat -c %s {remote_trace}').stdout)
                    reading = workload(section, name, llm, headers, stream, concurrency,
                                       args.warmup, args.seconds, rows)
                    record['cases'][name] = reading
                    if remote_trace:
                        end = int(device.shell(f'toybox stat -c %s {remote_trace}').stdout)
                        require(end > start and (end - start) % 16 == 0, 'audit sync trace did not record complete samples')
                        reading['syncTraceRangeBytes'] = [start, end]
                    if stats is not None:
                        metrics_snapshot(stats, section / f'{name}.after.prom')
                    save(out / 'report.json', report)
                begin = time.monotonic_ns()
                time.sleep(args.cooldown)
                record['cooldown'] = window(rows, 'gateway', begin, time.monotonic_ns())
                record['conditionsAfter'] = conditions(device)
                record['audit'] = audit_status(admin)
                if remote_trace:
                    device.run('pull', remote_trace, str(section / 'audit-sync.bin'))
        if args.profile:
            with running('profile') as (section, headers, _, pid, _):
                report['profile'] = profile(device, directory, pid, section, llm, headers)
                save(out / 'report.json', report)
        if args.soak:
            single = len(args.soak_protocols) == 1
            for protocol in args.soak_protocols:
                label = 'soak' if single else f'soak-{protocol}'
                with running(label) as (section, headers, rows, _, idle):
                    record = {'protocol': protocol, 'idle': idle, 'conditionsBefore': conditions(device),
                              'auditBefore': audit_status(admin)}
                    if single:
                        report['soak'] = record
                    else:
                        report.setdefault('soaks', {})[protocol] = record
                    if stats is not None:
                        before = metrics_snapshot(stats, section / 'before.prom')
                        workers = re.search(rb'^agentgateway_tokio_num_workers (\d+)$', before, re.MULTILINE)
                        require(workers is not None, 'gateway metrics did not expose the Tokio worker count')
                        record['effectiveWorkerThreads'] = int(workers[1])
                        if args.worker_threads is not None:
                            require(record['effectiveWorkerThreads'] == args.worker_threads,
                                    'gateway effective worker count differs from the requested configuration')
                    save(out / 'report.json', report)
                    record['load'] = workload(section, f'{protocol}-c8', llm, headers, protocol == 'sse',
                                              8, args.warmup, args.soak, rows)
                    if stats is not None:
                        metrics_snapshot(stats, section / 'after.prom')
                    begin = time.monotonic_ns()
                    time.sleep(args.cooldown)
                    record['cooldown'] = window(rows, 'gateway', begin, time.monotonic_ns())
                    record['conditionsAfter'] = conditions(device)
                    record['audit'] = audit_status(admin)
                save(out / 'report.json', report)
        report['conditionsAfter'] = conditions(device)
        report['startupDistributionMs'] = quantiles([row['ms'] for row in report['startupMs'] if row['session'].startswith('round-')])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--serial')
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--acceptance', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--concurrency', type=int, nargs='+', default=(1, 4, 8, 16))
    parser.add_argument('--seconds', type=float, default=10)
    parser.add_argument('--warmup', type=float, default=2)
    parser.add_argument('--idle', type=float, default=6)
    parser.add_argument('--cooldown', type=float, default=10)
    parser.add_argument('--soak', type=int, default=600)
    parser.add_argument('--soak-protocols', nargs='+', choices=('http', 'sse'), default=('sse',),
                        help='protocols for independent concurrency-8 soak windows, default SSE')
    parser.add_argument('--profile', action='store_true')
    parser.add_argument('--http-only', action='store_true', help='only run HTTP short windows')
    parser.add_argument('--worker-threads', type=int, help='set the gateway data-plane worker count')
    parser.add_argument('--collect-stages', action='store_true', help='save gateway histograms before and after each short window')
    parser.add_argument('--relay', type=Path, help='compiled Android loopback relay for a matched ADB control')
    parser.add_argument('--audit-sync-probe', type=Path, help='compiled Android audit timing library for separate probe runs')
    args = parser.parse_args()
    if not 1 <= args.rounds <= 5 or not all(1 <= value <= 32 for value in args.concurrency) or len(set(args.concurrency)) != len(args.concurrency):
        parser.error('use 1..5 rounds and unique concurrency levels in 1..32')
    if not 1 <= args.seconds <= 120 or not 0 <= args.warmup <= 60 or not 2 <= args.idle <= 60 or not 2 <= args.cooldown <= 60 or not 0 <= args.soak <= 900:
        parser.error('durations exceed the bounded workload')
    if args.worker_threads is not None and args.worker_threads < 1:
        parser.error('--worker-threads must be positive')
    if len(set(args.soak_protocols)) != len(args.soak_protocols):
        parser.error('--soak-protocols must contain unique protocols')
    os.umask(0o077)
    out = args.out.resolve()
    out.mkdir(parents=True)
    report = {'successful': False, 'startupMs': [], 'direct': {}, 'rounds': {},
              'parameters': {'rounds': args.rounds, 'concurrency': args.concurrency,
                             'warmupSeconds': args.warmup, 'measurementSeconds': args.seconds,
                             'idleSeconds': args.idle, 'cooldownSeconds': args.cooldown,
                             'soakSeconds': args.soak, 'soakProtocols': args.soak_protocols, 'httpOnly': args.http_only,
                             'workerThreads': args.worker_threads, 'collectStages': args.collect_stages,
                             'adbRelay': bool(args.relay), 'auditSyncProbe': bool(args.audit_sync_probe)}}
    try:
        run(args, out, report)
        report['successful'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        save(out / 'report.json', report)


if __name__ == '__main__':
    main()
