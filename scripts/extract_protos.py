#!/usr/bin/env python3
"""Extract serialized FileDescriptorProto blobs from a Mach-O binary
and reconstruct .proto source files.

Usage: python3 extract_protos.py <binary_path> <output_dir>
"""

import sys
import os
import re
from google.protobuf import descriptor_pb2

FDP = descriptor_pb2.FieldDescriptorProto

SCALAR_TYPE_NAMES = {
    FDP.TYPE_DOUBLE: 'double', FDP.TYPE_FLOAT: 'float',
    FDP.TYPE_INT64: 'int64', FDP.TYPE_UINT64: 'uint64',
    FDP.TYPE_INT32: 'int32', FDP.TYPE_FIXED64: 'fixed64',
    FDP.TYPE_FIXED32: 'fixed32', FDP.TYPE_BOOL: 'bool',
    FDP.TYPE_STRING: 'string', FDP.TYPE_BYTES: 'bytes',
    FDP.TYPE_UINT32: 'uint32', FDP.TYPE_SFIXED32: 'sfixed32',
    FDP.TYPE_SFIXED64: 'sfixed64', FDP.TYPE_SINT32: 'sint32',
    FDP.TYPE_SINT64: 'sint64',
}

VALID_IDENT = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')
VALID_PROTO_NAME = re.compile(r'^[a-zA-Z0-9_/.\-]+\.proto$')


def is_valid_ident(name):
    return bool(VALID_IDENT.match(name)) if name else False


def read_varint(data, offset):
    result, shift = 0, 0
    while offset < len(data) and shift < 35:
        b = data[offset]
        result |= (b & 0x7f) << shift
        shift += 7
        offset += 1
        if not (b & 0x80):
            return result, offset
    return None, offset


# -- Binary scanning -----------------------------------------------------------

def find_proto_offsets(data):
    """Find byte offsets that look like starts of FileDescriptorProto messages."""
    offsets = []
    i = 0
    while i < len(data) - 10:
        # Tag 0x0a = field 1 (name), wire type 2 (length-delimited)
        if data[i] != 0x0a:
            i += 1
            continue
        slen, start = read_varint(data, i + 1)
        if slen and 5 <= slen <= 300 and start + slen <= len(data):
            try:
                name = data[start:start + slen].decode('ascii')
                if VALID_PROTO_NAME.match(name):
                    offsets.append((i, name))
            except (UnicodeDecodeError, ValueError):
                pass
        i += 1
    return offsets


def score_fdp(fdp):
    """Score how much valid content a parsed FileDescriptorProto has."""
    score = 0
    for msg in fdp.message_type:
        if is_valid_ident(msg.name):
            score += 1 + sum(1 for f in msg.field if is_valid_ident(f.name))
    for enum in fdp.enum_type:
        if is_valid_ident(enum.name):
            score += 1 + sum(1 for v in enum.value if is_valid_ident(v.name))
    for svc in fdp.service:
        if is_valid_ident(svc.name):
            score += 1
    return score


def extract_descriptors(data):
    """Extract FileDescriptorProto messages from binary data."""
    offsets = find_proto_offsets(data)
    print(f"  Found {len(offsets)} candidate offsets")

    results = {}
    for idx, (offset, name) in enumerate(offsets):
        # Bound chunk size: up to next candidate or 512KB max
        next_off = offsets[idx + 1][0] if idx + 1 < len(offsets) else len(data)
        max_chunk = min(next_off - offset, 524288)

        best, best_score = None, 0
        try_sizes = sorted(set([max_chunk, max_chunk // 2, 4096, 16384, 65536, 262144]))
        for size in try_sizes:
            if size < 256 or size > max_chunk:
                continue
            chunk = data[offset:offset + size]
            fdp = descriptor_pb2.FileDescriptorProto()
            try:
                fdp.ParseFromString(chunk)
            except Exception:
                continue
            if fdp.name != name:
                continue
            s = score_fdp(fdp)
            if s > best_score:
                best_score = s
                best = descriptor_pb2.FileDescriptorProto()
                best.CopyFrom(fdp)

        if best and best_score > 0:
            prev = results.get(name)
            if not prev or best_score > prev[1]:
                results[name] = (best, best_score)
                print(f"  {name}: {len(best.message_type)} msgs, "
                      f"{len(best.enum_type)} enums, {len(best.service)} svcs "
                      f"(score {best_score})")

    return {n: fdp for n, (fdp, _) in results.items()}


# -- .proto reconstruction ----------------------------------------------------

def field_type_str(field):
    t = SCALAR_TYPE_NAMES.get(field.type)
    return t if t else field.type_name.lstrip('.')


def is_map_entry(msg):
    return (msg.HasField('options') and
            msg.options.HasField('map_entry') and
            msg.options.map_entry)


def ind(level):
    return '  ' * level


def fmt_enum(enum, lvl=0):
    if not is_valid_ident(enum.name):
        return []
    lines = [f'{ind(lvl)}enum {enum.name} {{']
    for v in enum.value:
        if is_valid_ident(v.name):
            lines.append(f'{ind(lvl+1)}{v.name} = {v.number};')
    lines.append(f'{ind(lvl)}}}')
    return lines


def fmt_message(msg, lvl=0):
    if not is_valid_ident(msg.name) or is_map_entry(msg):
        return []
    lines = [f'{ind(lvl)}message {msg.name} {{']

    # Nested enums
    for e in msg.enum_type:
        el = fmt_enum(e, lvl + 1)
        if el:
            lines.extend(el)
            lines.append('')

    # Nested messages (skip map entries)
    for n in msg.nested_type:
        if not is_map_entry(n):
            ml = fmt_message(n, lvl + 1)
            if ml:
                lines.extend(ml)
                lines.append('')

    # Map entry lookup for map field detection
    map_entries = {n.name: n for n in msg.nested_type if is_map_entry(n)}

    # Collect real oneof fields (not proto3 optional synthetic oneofs)
    oneof_fields = {}
    for f in msg.field:
        if f.HasField('oneof_index') and not f.proto3_optional:
            oneof_fields.setdefault(f.oneof_index, []).append(f)

    written = set()
    for oi, od in enumerate(msg.oneof_decl):
        if oi in oneof_fields and is_valid_ident(od.name):
            lines.append(f'{ind(lvl+1)}oneof {od.name} {{')
            for f in oneof_fields[oi]:
                if is_valid_ident(f.name):
                    lines.append(f'{ind(lvl+2)}{field_type_str(f)} {f.name} = {f.number};')
                    written.add(f.number)
            lines.append(f'{ind(lvl+1)}}}')
            lines.append('')

    # Regular fields
    for f in msg.field:
        if f.number in written or not is_valid_ident(f.name):
            continue

        # Map field detection
        if f.type == FDP.TYPE_MESSAGE and f.label == FDP.LABEL_REPEATED:
            entry_name = f.type_name.split('.')[-1]
            if entry_name in map_entries:
                me = map_entries[entry_name]
                kf = next((x for x in me.field if x.number == 1), None)
                vf = next((x for x in me.field if x.number == 2), None)
                if kf and vf:
                    lines.append(f'{ind(lvl+1)}map<{field_type_str(kf)}, {field_type_str(vf)}> '
                                 f'{f.name} = {f.number};')
                    continue

        label = ''
        if f.label == FDP.LABEL_REPEATED:
            label = 'repeated '
        elif f.label == FDP.LABEL_REQUIRED:
            label = 'required '
        elif f.proto3_optional:
            label = 'optional '

        lines.append(f'{ind(lvl+1)}{label}{field_type_str(f)} {f.name} = {f.number};')

    lines.append(f'{ind(lvl)}}}')
    return lines


def fmt_service(svc, lvl=0):
    if not is_valid_ident(svc.name):
        return []
    lines = [f'{ind(lvl)}service {svc.name} {{']
    for m in svc.method:
        if not is_valid_ident(m.name):
            continue
        cs = 'stream ' if m.client_streaming else ''
        ss = 'stream ' if m.server_streaming else ''
        inp = m.input_type.lstrip('.')
        out = m.output_type.lstrip('.')
        lines.append(f'{ind(lvl+1)}rpc {m.name} ({cs}{inp}) returns ({ss}{out});')
    lines.append(f'{ind(lvl)}}}')
    return lines


def fdp_to_proto(fdp):
    """Reconstruct a .proto source file from a FileDescriptorProto."""
    parts = []
    syntax = fdp.syntax or 'proto2'
    parts.append(f'syntax = "{syntax}";\n')

    if fdp.package:
        parts.append(f'package {fdp.package};\n')

    for dep in fdp.dependency:
        parts.append(f'import "{dep}";')
    if fdp.dependency:
        parts.append('')

    for e in fdp.enum_type:
        el = fmt_enum(e)
        if el:
            parts.append('\n'.join(el))

    for m in fdp.message_type:
        ml = fmt_message(m)
        if ml:
            parts.append('\n'.join(ml))

    for s in fdp.service:
        sl = fmt_service(s)
        if sl:
            parts.append('\n'.join(sl))

    return '\n\n'.join(parts) + '\n'


# -- Main ---------------------------------------------------------------------

def main():
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} <binary> <output_dir>')
        sys.exit(1)

    binary_path, output_dir = sys.argv[1], sys.argv[2]

    print(f'Reading {binary_path}')
    with open(binary_path, 'rb') as f:
        data = f.read()
    print(f'Size: {len(data):,} bytes\n')

    print('Scanning for FileDescriptorProto blobs...')
    descriptors = extract_descriptors(data)

    if not descriptors:
        print('\nNo FileDescriptorProto blobs found.')
        sys.exit(0)

    print(f'\nReconstructing {len(descriptors)} .proto files...')
    os.makedirs(output_dir, exist_ok=True)

    for name, fdp in sorted(descriptors.items()):
        out_path = os.path.join(output_dir, name)
        dirname = os.path.dirname(out_path)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        with open(out_path, 'w') as f:
            f.write(fdp_to_proto(fdp))
        print(f'  Wrote {out_path}')

    print(f'\nDone! Extracted {len(descriptors)} .proto files to {output_dir}')


if __name__ == '__main__':
    main()
