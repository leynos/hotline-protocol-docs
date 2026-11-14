#!/usr/bin/env python3
# fmt: off
"""Replay the three disposable-lab A7 transfers from frozen packet captures."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path

from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import verify_capture

PLAN_SHA = '5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e'
DRIVER_SHA = '2fba0972f4d9a8e3845c4204dce150dd7c90da0e19a9e5720d5289e2c94faf01'
FULL_SHA = '7d1f5bf5e2b69b8a18906633ce2ef550876b78252c0639e7d36eb61142787ab8'
PREFIX_SHA = 'b4c6dc15be0d82de42d3aa7102c1feca67397b978591ac8be2d2c846d6a62e7c'
ROM_SHA = '18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd'
BASE_SHA = 'e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910'
EXE_SHA = '9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4'
APP_SHA = 'ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b'
PREFS_SHA = '4ed2b3e14e6e8a6cf246d16f7d1b98f0b91d1b09f6ab5497de1056a6f617d196'
NORMAL_PREFS_SHA = 'f8809e5435f85ee17d5ca2c61b29c71b4fdca0db881f9b6b2a9e24b1fda1d6e2'
RUNS = {'c32': 15720, 'c35': 15730, 'c45': 15740}

def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def load(path: Path) -> dict:
    return json.loads(path.read_text())

def inventory(corpus: Path) -> None:
    manifest = load(corpus / 'manifest.json')
    require(manifest['schema'] == 'native-transfer-repeat-01', 'Corpus schema differs')
    files = manifest['files']
    actual = {str(path.relative_to(corpus)) for path in corpus.rglob('*') if path.is_file() and path.name not in {'manifest.json', 'SHA256SUMS'}}
    require(actual == set(files), 'Corpus inventory differs')
    for name, digest in files.items():
        require(sha((corpus / name).read_bytes()) == digest, f'Corpus SHA differs: {name}')
    lines = [f'{digest}  {name}' for name, digest in sorted(files.items())]
    require((corpus / 'SHA256SUMS').read_text().splitlines() == lines, 'SHA list differs')
    provenance = load(corpus / 'source-provenance.json')
    require(provenance['schema'] == manifest['schema'], 'Provenance schema differs')
    require(set(provenance['sources']) == set(files) - {'source-provenance.json'}, 'Source set differs')
    for name, record in provenance['sources'].items():
        data = (corpus / name).read_bytes()
        require(sha(data) == record['sha256'] and len(data) == record['bytes'], f'Source differs: {name}')

def verify(corpus: Path) -> dict:
    corpus = corpus.resolve()
    inventory(corpus)
    comparison = load(corpus / 'analysis/packet-comparison.json')['runs']
    configs = load(corpus / 'analysis/config-comparison.json')
    require(set(comparison) == set(configs) == set(RUNS), 'Comparison run set differs')
    require(sha(Path(__file__).with_name('protocol_capture.py').read_bytes()) == DRIVER_SHA, 'Capture driver revision differs')
    summary = {}
    bodies = {}
    for run, frontend in RUNS.items():
        root = corpus / 'runs' / run
        original = load(root / 'original-plan.json')
        plan = load(root / 'a7-as-run-plan.json')
        require(sha((root / 'original-plan.json').read_bytes()) == PLAN_SHA, f'{run} source A7 differs')
        require(len(original['steps']) == 29 and original['steps'] == plan['steps'], f'{run} A7 steps differ')
        for key in original.keys() - {'operator', 'environment', 'endpoints'}:
            require(original[key] == plan[key], f'{run} A7 {key} differs')
        require(plan['endpoints'] == {
            'control': {'host': '127.0.0.1', 'port': frontend},
            'data': {'host': '127.0.0.1', 'port': frontend + 1},
        }, f'{run} endpoint differs')
        options = plan['environment']['original_options']
        limits = (options['server_port'], options['global_max_downloads'],
                  options['per_client_max_downloads'], options['max_connections_per_ip'])
        require(limits == (5500, 100, 10, 5), f'{run} recorded options differ')
        require(plan['environment']['captured_options'] is False, f'{run} lab GUI-options observation changed')
        report = verify_capture(root / 'capture')
        expected_status, expected_actions, expected_len, expected_sha = (
            ('completed', 29, 1049073, FULL_SHA) if run == 'c32'
            else ('failed', 21, 98304, PREFIX_SHA)
        )
        observed = (report['status'], report['completed_actions'], report['error'])
        expected = (expected_status, expected_actions,
                    '' if run == 'c32' else 'TimeoutError: timed out')
        require(observed == expected, f'{run} A7 outcome differs')
        require(report['driver_sha256'] == DRIVER_SHA, f'{run} capture driver differs')
        require(report['oracle_sha256'] == APP_SHA, f'{run} native app differs')
        received = bytes.fromhex(report['streams']['download']['received_hex'])
        sent = bytes.fromhex(report['streams']['download']['sent_hex'])
        require(len(received) == expected_len and sha(received) == expected_sha, f'{run} recorder body differs')
        event = next(e for e in report['events'] if e['connection'] == 'download' and e['event'] == 'connect')
        require(event['peer_address'] == ['127.0.0.1', frontend + 1], f'{run} data peer differs')
        local = event['local_address'][1]
        when = int(dt.datetime.fromisoformat(report['started_at_utc']).timestamp() * 1000000) + event['elapsed_ns'] // 1000
        views = {}
        for name, client, server, port, filename in (
            ('namespace', '127.0.0.1', '127.0.0.1', frontend + 1, 'lab-namespace.pcap'),
            ('guest', '10.0.2.2', '10.0.2.15', 5501, 'lab-guest.pcap'),
        ):
            packets = read_packets(root / 'boot' / filename)
            if name == 'namespace':
                require(not any(15500 <= p['src_port'] <= 15501 or 15500 <= p['dst_port'] <= 15501 for p in packets), f'{run} primary bridge used')
            flow = lifetime(packets, (client, local), (server, port), when)
            require(sum(bool(p['flags'] & 2 and (not p['flags'] & 16)) for p in flow) == 1, f'{run} {name} SYN association differs')
            actual = stream(flow, (server, port), (client, local))
            require(actual == received, f'{run} {name} payload differs')
            require(stream(flow, (client, local), (server, port)) == sent, f'{run} {name} HTXF differs')
            require(len(actual) == expected_len and sha(actual) == expected_sha, f'{run} {name} length differs')
            prior = comparison[run]['views'][name]
            require(prior['pcap_sha256'] == sha((root / 'boot' / filename).read_bytes()), f'{run} {name} source PCAP differs')
            require(prior['server_bytes'] == len(actual) and prior['server_sha256'] == sha(actual), f'{run} {name} comparison differs')
            views[name] = len(actual)
        require(read_packets(root / 'boot/primary-host.pcap') == [], f'{run} host primary contact')
        for log in ('host-recorder.log', 'ns-recorder.log'):
            require('0 packets dropped by kernel' in (root / 'boot' / log).read_text(), f'{run} recorder drops unknown')
        assets = load(root / 'assets.json')
        cfg = configs[run]
        require(assets['rom_sha256'] == ROM_SHA and assets['base_disk_sha256'] == BASE_SHA, f'{run} source assets differ')
        require(cfg['source_assets'] == assets and cfg['emulator_exe_sha256'] == EXE_SHA
                and cfg['native_oracle_sha256'] == APP_SHA, f'{run} binary identity differs')
        require(cfg['guest_prefs_sha256'] == PREFS_SHA and cfg['guest_prefs_bytes'] == 175, f'{run} offline guest prefs differ')
        prefs = (root / 'sheep-prefs.txt').read_text()
        require(sha(prefs.encode()) == cfg['sheep_prefs_sha256'] and cfg['sheep_prefs_normalized_sha256'] == NORMAL_PREFS_SHA, f'{run} emulator prefs differ')
        require('ramsize 536870912' in prefs and 'ether slirp' in prefs, f'{run} RAM or network mode differs')
        ready = load(root / 'boot/readiness.json')
        require((ready.get('exe_sha256') or ready.get('emulator_sha256')) == EXE_SHA, f'{run} ready executable differs')
        launch = load(root / 'boot/lab-launch.json')['argv']
        require('--isolate-network' in launch and '--service' in launch and (str(frontend) in launch), f'{run} launch differs')
        terminal = load(root / 'terminal.json')
        if run == 'c45':
            require(terminal['actual_pid_gone'] and terminal['owned_frontend_absent'], 'C45 lab retirement differs')
            require(terminal['guard_seed_ban_probe'].startswith('not run'), 'C45 option-two scope differs')
            require('/proc' in terminal['cleanup_anomaly'] and 'exit5' in terminal['cleanup_anomaly'], 'C45 cleanup anomaly lost')
            require(all(v['primary_syn_count'] == 0 for v in terminal['primary_syn_views'].values()), 'C45 primary SYN differs')
        else:
            require(terminal['processes']['lab']['exists'] is False, f'{run} lab retirement differs')
            require(all(v.get('syn_count', v.get('syn_lines')) == 0 for v in terminal['primary_syn'].values()), f'{run} primary SYN differs')
            if run == 'c35':
                require(terminal['guard_seed_ban_probe_executed'] is False, 'C35 option-two scope differs')
        bodies[run] = received
        summary[run] = {'status': expected_status, 'bytes': expected_len, 'views': views}
    require(bodies['c35'] == bodies['c45'] == bodies['c32'][:98304], 'Repeated prefixes differ')
    return summary

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('corpus', type=Path)
    print(json.dumps(verify(parser.parse_args().corpus), indent=2))
if __name__ == '__main__':
    main()
# fmt: on
