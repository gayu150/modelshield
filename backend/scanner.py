"""Read-only structural signals. No model loader or pickle deserialization runs here."""
import hashlib
import io
import json
import pickletools
import stat
import struct
import tarfile
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .config import SCAN_PREFIX_BYTES

EXTENSIONS = {'.pkl', '.pickle', '.pt', '.pth', '.onnx', '.safetensors',
              '.h5', '.hdf5', '.zip', '.tar', '.gz'}
HDF5_MAGIC = b'\x89HDF\r\n\x1a\n'
PICKLE_RISK_OPS = {'GLOBAL', 'STACK_GLOBAL', 'REDUCE', 'INST', 'OBJ',
                   'NEWOBJ', 'NEWOBJ_EX', 'EXT1', 'EXT2', 'EXT4'}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def digest(path: Path):
    sha = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            sha.update(block)
    return sha.hexdigest()


def validate_content(path: Path, extension: str, mime: str | None):
    if extension not in EXTENSIONS:
        raise ValueError('Unsupported file format.')
    if mime and (mime.startswith('text/') or mime.startswith('image/') or mime in {'application/pdf', 'text/html'}):
        raise ValueError('File media type does not match a model artifact.')
    with path.open('rb') as stream:
        head = stream.read(8192)
    if not head:
        raise ValueError('File is empty.')
    if extension in {'.zip', '.pt', '.pth'} and head.startswith(b'PK\x03\x04'):
        if not zipfile.is_zipfile(path):
            raise ValueError('Invalid ZIP container.')
    elif extension == '.zip':
        raise ValueError('Invalid ZIP container.')
    elif extension in {'.h5', '.hdf5'} and not any(head[offset:offset + 8] == HDF5_MAGIC for offset in (0, 512, 1024, 2048, 4096)):
        raise ValueError('Invalid HDF5 signature.')
    elif extension == '.safetensors':
        if len(head) < 9:
            raise ValueError('Invalid safetensors header.')
        header_bytes = struct.unpack('<Q', head[:8])[0]
        if header_bytes > 100 * 1024 * 1024 or header_bytes + 8 > path.stat().st_size:
            raise ValueError('Invalid safetensors header size.')
        with path.open('rb') as stream:
            stream.seek(8)
            try:
                header = json.loads(stream.read(header_bytes))
            except (UnicodeError, json.JSONDecodeError):
                raise ValueError('Invalid safetensors metadata.') from None
        if not isinstance(header, dict):
            raise ValueError('Invalid safetensors metadata.')
    elif extension == '.tar' and not tarfile.is_tarfile(path):
        raise ValueError('Invalid TAR container.')
    elif extension == '.gz' and not head.startswith(b'\x1f\x8b'):
        raise ValueError('Invalid GZIP header.')
    elif extension == '.onnx':
        # A ModelProto commonly begins with field 1 (ir_version). This is a
        # minimal structural check, not a full ONNX parser or semantic validation.
        if head[0] != 0x08 or len(head) < 2:
            raise ValueError('Unrecognized ONNX protobuf header.')
    elif extension in {'.pkl', '.pickle'} and head[0] not in b'\x80(cIiJKNM]})UUXVSTFGhjqrlp0123456789':
        raise ValueError('Unrecognized pickle header.')
    elif extension in {'.pt', '.pth'} and head[0] != 0x80:
        raise ValueError('Unrecognized PyTorch artifact container.')


def report(path: Path, extension: str, expected_hash: str):
    findings = []
    evidence = []
    nodes = []
    edges = []
    seen_at = utc_now()

    def add_signal(title, severity, description, recommendation, detail):
        fid, eid = str(uuid.uuid4()), str(uuid.uuid4())
        findings.append({'id': fid, 'title': title, 'severity': severity,
                         'description': description, 'scanner': 'ModelShield structural scanner',
                         'scannerVersion': '1', 'evidenceIds': [eid],
                         'recommendation': recommendation})
        evidence.append({'id': eid, 'title': title + ' evidence', 'kind': 'STATIC_ANALYSIS',
                         'timestamp': seen_at, 'summary': description,
                         'content': detail[:4000], 'scanner': 'ModelShield structural scanner'})
        return fid, eid

    observed = digest(path)
    if observed != expected_hash:
        add_signal('Artifact bytes changed', 'CRITICAL',
                   'The stored file no longer matches its intake fingerprint.',
                   'Quarantine the artifact and investigate storage integrity.',
                   'Expected SHA-256: ' + expected_hash + '\nObserved SHA-256: ' + observed)
    size = path.stat().st_size
    with path.open('rb') as stream:
        prefix = stream.read(SCAN_PREFIX_BYTES + 1)
    limited = len(prefix) > SCAN_PREFIX_BYTES
    prefix = prefix[:SCAN_PREFIX_BYTES]

    if extension in {'.pkl', '.pickle', '.pt', '.pth'} and not prefix.startswith(b'PK\x03\x04'):
        try:
            risky = set()
            for opcode, _argument, _offset in pickletools.genops(prefix):
                if opcode.name in PICKLE_RISK_OPS:
                    risky.add(opcode.name)
            if risky:
                add_signal('Executable pickle operations', 'HIGH',
                           'Pickle instructions capable of invoking constructors or globals were found.',
                           'Do not deserialize this artifact in a trusted process; review its origin and isolated scan results.',
                           'Observed opcodes: ' + ', '.join(sorted(risky)))
        except (ValueError, EOFError, IndexError) as exc:
            add_signal('Pickle structure could not be fully parsed', 'MEDIUM',
                       'Static pickle parsing stopped before the artifact could be fully inspected.',
                       'Review the artifact with an isolated parser and a trusted publisher.',
                       type(exc).__name__)

    if prefix.startswith(b'PK\x03\x04'):
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > 100_000:
                add_signal('Excessive archive entries', 'HIGH',
                           'The archive has more than 100,000 entries.',
                           'Inspect in a bounded isolated environment.', str(len(members)))
                members = members[:100_000]
            unsafe_names = [m.filename for m in members if _unsafe_path(m.filename) or
                            stat.S_IFMT(m.external_attr >> 16) == stat.S_IFLNK]
            bombs = [m.filename for m in members if m.file_size > 4 * 1024**3 or
                     (m.compress_size and m.file_size / m.compress_size > 1000)]
            if unsafe_names:
                add_signal('Archive traversal paths', 'HIGH',
                           'Archive entries contain absolute or parent paths.',
                           'Do not extract this archive without rejecting unsafe paths.',
                           ', '.join(unsafe_names[:20]))
            if bombs:
                add_signal('Excessive archive expansion', 'HIGH',
                           'Archive metadata indicates very large expansion.',
                           'Use resource limits and inspect the archive in isolation.',
                           ', '.join(bombs[:20]))
            pickle_members = [m.filename for m in members if m.filename.lower().endswith(('.pkl', '.pickle'))]
            if pickle_members:
                add_signal('Embedded pickle payload', 'HIGH',
                           'The archive contains pickle data; its contents were not deserialized.',
                           'Review embedded data in an isolated environment before loading.',
                           ', '.join(pickle_members[:20]))
    elif extension == '.tar':
        with tarfile.open(path, 'r:') as archive:
            unsafe = []
            for index, member in enumerate(archive):
                if index >= 100_000:
                    add_signal('Excessive archive entries', 'HIGH',
                               'The TAR has more than 100,000 entries.',
                               'Inspect in a bounded isolated environment.', str(index + 1))
                    break
                if _unsafe_path(member.name) or member.issym() or member.islnk():
                    unsafe.append(member.name)
            if unsafe:
                add_signal('Unsafe TAR member', 'HIGH',
                           'The TAR contains traversal paths or links.',
                           'Reject unsafe members before any extraction.', ', '.join(unsafe[:20]))

    if limited or extension in {'.onnx', '.safetensors', '.h5', '.hdf5', '.gz'}:
        reason = ('Only the first 64 MiB was inspected.' if limited else
                  'This format received structural validation only; no semantic or malware analysis ran.')
        add_signal('Analysis coverage is limited', 'INFO', reason,
                   'Obtain a format-aware isolated scan before a release decision.',
                   'Format: ' + extension + '; size: ' + str(size) + ' bytes')

    evidence.insert(0, {'id': str(uuid.uuid4()), 'title': 'Artifact integrity fingerprint',
                        'kind': 'INTEGRITY', 'timestamp': seen_at,
                        'summary': 'Stored bytes were hashed without loading the model.',
                        'content': 'SHA-256: ' + observed, 'scanner': 'ModelShield integrity check'})
    return findings, evidence, observed


def _unsafe_path(name: str):
    normalized = name.replace('\\', '/')
    parts = PurePosixPath(normalized).parts
    return normalized.startswith('/') or '..' in parts or ':' in parts[0] if parts else False
