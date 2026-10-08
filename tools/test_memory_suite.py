"""One-command memory regression gate; never builds, publishes or touches an SD card."""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {'Unleashed': ('f7-firmware', 85), 'Momentum': ('f7-firmware-C', 86),
           'Official': ('f7-firmware-C', 85)}
HOST_TESTS = ('test_box_flash_archive.py', 'test_preflight_lease.py',
              'test_pure_hardware.py', 'test_spi_headers.py', 'test_aio_versions.py', 'test_version_names.py', 'test_version_navigation.py', 'test_memory_suite_checks.py')
EVIDENCE = ('source-snapshot.json', 'memory.json', 'loader.json', 'status-stack.json')


def sha(path):
    """Hash a local input without exposing its contents in reports."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def source_matches(snapshot, root=ROOT):
    """Reject changed/deleted inputs AND newly added build inputs."""
    expected = {'application.fam'}
    for folder in ('src', 'config', 'assets'):
        expected.update(p.relative_to(root).as_posix() for p in (root / folder).rglob('*') if p.is_file())
    normalized = {name.replace('\\', '/'): digest for name, digest in snapshot.items()}
    if not expected <= normalized.keys():
        raise ValueError('Build snapshot is incomplete; rebuild the selected target.')
    for name, digest in normalized.items():
        path = (root / name).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file() or sha(path) != digest:
            raise ValueError(f'Stale build input: {name}; rebuild the selected target.')


def validate_evidence(directory, fap, binary_dir):
    """Tie saved checks, actual FAP and ARM debug binaries to one exact build."""
    source_matches(read_json(directory / 'source-snapshot.json'))
    digest = sha(fap)
    for filename, key in [('memory.json', 'sha256'), ('loader.json', 'sha256'),
                          ('status-stack.json', 'fap_sha256')]:
        data = read_json(directory / filename)
        if data.get(key) != digest:
            raise ValueError(f'{filename} belongs to a different FAP; rebuild.')
    if sha(binary_dir / 'tb2_probe.fap') != digest:
        raise ValueError('SDK output differs from candidate; rebuild the selected target.')
    stack = read_json(directory / 'status-stack.json')
    if not stack.get('passed') or not stack.get('elf_sha256'):
        raise ValueError('Missing or failed ARM stack evidence.')
    for module, digest in stack['elf_sha256'].items():
        if sha(binary_dir / f'{module}_d.elf') != digest:
            raise ValueError(f'Stale ARM stack input: {module}; rebuild.')


def register(args):
    """Called only after the existing build gates have completed successfully."""
    if not args.target or not args.sdk or not args.fap:
        raise ValueError('--register requires --target, --sdk and --fap.')
    variant, manifest = TARGETS[args.target]
    binaries = args.sdk.resolve() / 'build' / variant / '.extapps'
    validate_evidence(args.register, args.fap, binaries)
    target_dir = ROOT / 'build/targets' / args.target
    target_dir.mkdir(parents=True, exist_ok=True)
    for name in EVIDENCE:
        source = args.register / name
        target = target_dir / name
        if source.resolve() != target.resolve():
            shutil.copyfile(source, target)
    receipt = {'target': args.target, 'sdk': str(args.sdk.resolve()),
               'fap': str(args.fap.resolve()), 'binary_dir': str(binaries),
               'manifest_size': manifest}
    (target_dir / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(f'Registered current {args.target} build for TEST-MEMORY.')


def host_command():
    """Use a native C compiler or probe WSL once; missing tools are a failure."""
    if shutil.which(os.environ.get('CC', 'cc')):
        return [sys.executable], ROOT
    if os.name != 'nt' or not shutil.which('wsl.exe'):
        raise ValueError('Host regressions require cc (or WSL with python3 and cc).')
    subprocess.run(['wsl.exe', '--exec', 'sh', '-c', 'command -v python3 && command -v cc'],
                   check=True, capture_output=True, text=True, timeout=15)
    path = subprocess.check_output(['wsl.exe', '--exec', 'wslpath', '-a', str(ROOT)],
                                   text=True, timeout=15).strip()
    return ['wsl.exe', '--exec', 'python3'], Path(path)


class Suite:
    """Continue independent checks, retain detailed logs, return one failing exit code."""

    def __init__(self, output):
        self.output = output
        self.output.mkdir(parents=True, exist_ok=True)
        self.results = []

    def check(self, name, action):
        started = time.monotonic()
        try:
            note = action() or ''
            passed = True
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            note, passed = str(error), False
        self.results.append({'name': name, 'passed': passed, 'note': note,
                             'seconds': round(time.monotonic() - started, 2)})
        print(f'{"PASS" if passed else "FAIL"}: {name}' + (f' - {note}' if note else ''))
        return passed

    def command(self, name, command):
        with (self.output / (name + '.log')).open('w', encoding='utf-8') as log:
            result = subprocess.run([str(part) for part in command], cwd=ROOT,
                                    stdout=log, stderr=subprocess.STDOUT, timeout=180, check=False)
        if result.returncode:
            raise ValueError(f'exit {result.returncode}; see {name}.log')

    def target(self, target):
        directory = ROOT / 'build/targets' / target
        if not (directory / 'receipt.json').is_file():
            raise ValueError(f'No registered {target} build. Run BUILD-{target}.cmd first.')
        receipt = read_json(directory / 'receipt.json')
        if receipt['target'] != target:
            raise ValueError('Wrong build receipt target.')
        fap, sdk, binaries = map(Path, (receipt['fap'], receipt['sdk'], receipt['binary_dir']))
        validate_evidence(directory, fap, binaries)
        reports = self.output / target
        reports.mkdir(exist_ok=True)
        commands = {
            'memory': ['check_fap_memory.py', fap, '--report', reports / 'memory.json'],
            'loader': ['check_fap_loader.py', fap, '--module-dir', binaries, '--api',
                       sdk / 'targets/f7/api_symbols.csv', '--manifest-size', receipt['manifest_size'],
                       '--report', reports / 'loader.json'],
            'stack': ['check_status_stack.py', '--firmware-root', sdk, '--binary-dir', binaries,
                      '--report', reports / 'stack.json'],
        }
        for name, arguments in commands.items():
            self.command(f'{target}-{name}', [sys.executable, ROOT / 'tools' / arguments[0], *arguments[1:]])
        memory = read_json(reports / 'memory.json')
        policy = read_json(ROOT / 'config/fap_memory.json')
        margin = policy['browser_payload_max'] - memory['browser_payload']
        return f'selection headroom {margin} B; processing {memory["resident_payload"]} B'

    def finish(self, scope):
        passed = bool(self.results) and all(item['passed'] for item in self.results)
        report = {'passed': passed, 'scope': scope, 'checks': self.results,
                  'limitation': 'Regression and artifact gate; not a measurement of device free heap or fragmentation.'}
        (self.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        lines = [f'MEMORY SUITE: {"PASS" if passed else "FAIL"} ({scope})', '', report['limitation'], '']
        lines += [f'{"PASS" if x["passed"] else "FAIL"} {x["name"]}: {x["note"]}' for x in self.results]
        (self.output / 'REPORT.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        print(lines[0])
        print(f'Report: {self.output / "REPORT.txt"}')
        return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument('--host-only', action='store_true', help='Regression checks only; no artifact acceptance')
    scope.add_argument('--artifacts-only', action='store_true')
    parser.add_argument('--target', choices=TARGETS, help='Default: all three firmware targets')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/memory-suite')
    parser.add_argument('--register', type=Path, help='Build evidence directory (called by build.ps1)')
    parser.add_argument('--sdk', type=Path)
    parser.add_argument('--fap', type=Path)
    args = parser.parse_args()
    if args.register:
        register(args)
        return 0
    suite = Suite(args.output)
    if not args.artifacts_only:
        command = []
        def prepare():
            prefix, root = host_command()
            command.extend([prefix, root])
        if suite.check('host-toolchain', prepare):
            prefix, root = command
            for script in HOST_TESTS:
                # WSL paths must retain forward slashes when assembled on Windows.
                path = str(root).replace('\\', '/') + '/tools/' + script
                suite.check(script, lambda script=script, path=path: suite.command(script, [*prefix, path]))
    if not args.host_only:
        for target in [args.target] if args.target else TARGETS:
            suite.check(target, lambda target=target: suite.target(target))
    return suite.finish('host-only' if args.host_only else 'artifacts-only' if args.artifacts_only else 'full')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f'MEMORY SUITE FAIL: {exc}', file=sys.stderr)
        sys.exit(1)
