#!/usr/bin/env python3
"""Extract serialized FileDescriptorProto blobs from a Mach-O binary
and reconstruct .proto source files.

Tries multiple strategies:
1. Scan for field-1 (name) tags pointing to .proto filenames
2. Scan for syntax field markers (proto3/proto2) and backtrack to find message start
3. Try to parse entire __DATA segments as FileDescriptorSet

Usage: python3 extract_protos.py <binary_path> <output_dir>
"""

import sys
import os
import re
import struct
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


# -- Strategy 1: Scan for .proto name fields -----------------------------------

def find_by_name_field(data):
    """Find FileDescriptorProto by scanning for field 1 (name) with .proto suffix."""
    offsets = []
    i = 0
    while i < len(data) - 10:
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

    print(f"  Strategy 1 (name field): {len(offsets)} raw candidates")

    # Show sample of unique names found
    unique_names = sorted(set(name for _, name in offsets))
    print(f"  Unique .proto names: {len(unique_names)}")
    for name in unique_names[:20]:
        print(f"    {name}")
    if len(unique_names) > 20:
        print(f"    ... and {len(unique_names) - 20} more")

    # For each unique name, collect all offsets. The serialized FDP likely
    # starts at the first occurrence where the gap to the next candidate
    # contains valid proto data.
    from collections import defaultdict
    name_offsets = defaultdict(list)
    for offset, name in offsets:
        name_offsets[name].append(offset)

    # Build deduped list: for each unique name, try each occurrence
    results = {}
    for name in unique_names:
        offs = name_offsets[name]
        best, best_score = None, 0

        for oi, offset in enumerate(offs):
            # Find the next candidate offset (any name) after this one
            # Binary search in the full sorted offset list
            next_off = None
            for o, n in offsets:
                if o > offset and n != name:
                    next_off = o
                    break
            if next_off is None:
                next_off = min(offset + 1048576, len(data))

            gap = next_off - offset
            # Try parsing with the gap as boundary
            for size in sorted(set([gap, gap // 2, 4096, 16384, 65536])):
                if size < 256 or size > gap:
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

            if best_score > 0:
                break  # Got a good parse, no need to try other occurrences

        if best and best_score > 0:
            results[name] = (best, best_score)
            print(f"    {name}: {len(best.message_type)} msgs, "
                  f"{len(best.enum_type)} enums, {len(best.service)} svcs "
                  f"(score {best_score})")

    print(f"  Parsed {len(results)}/{len(unique_names)} unique protos successfully")
    return {n: fdp for n, (fdp, _) in results.items()}


# -- Strategy 2: Scan for syntax markers and backtrack -------------------------

def find_by_syntax_marker(data):
    """Find FileDescriptorProto by locating syntax='proto3'/'proto2' markers."""
    # Field 12 (syntax), wire type 2 = tag 0x62, then varint length, then string
    markers = [b'\x62\x06proto3', b'\x62\x06proto2']
    syntax_offsets = []

    for marker in markers:
        pos = 0
        while True:
            idx = data.find(marker, pos)
            if idx == -1:
                break
            syntax_offsets.append(idx)
            pos = idx + 1

    print(f"  Strategy 2 (syntax marker): {len(syntax_offsets)} syntax markers found")

    results = {}
    for syn_off in syntax_offsets:
        # Backtrack: try parsing from offsets before the syntax field
        # The name field (field 1) must come before syntax (field 12)
        # Try at each 0x0a byte (potential field 1 tag) within 64KB before the marker
        search_start = max(0, syn_off - 65536)
        candidate_starts = []
        for j in range(search_start, syn_off):
            if data[j] == 0x0a:
                slen, s = read_varint(data, j + 1)
                if slen and 3 <= slen <= 300 and s + slen <= len(data):
                    try:
                        name = data[s:s + slen].decode('ascii')
                        # Accept any reasonable string, not just .proto
                        if re.match(r'^[a-zA-Z0-9_/.\-]+$', name):
                            candidate_starts.append((j, name))
                    except (UnicodeDecodeError, ValueError):
                        pass

        # Try parsing the most promising candidates (those closest to the syntax marker)
        for start, name in reversed(candidate_starts[-50:]):
            end = min(syn_off + 256, len(data))
            chunk = data[start:end]
            fdp = descriptor_pb2.FileDescriptorProto()
            try:
                fdp.ParseFromString(chunk)
            except Exception:
                continue
            if fdp.syntax and fdp.name and score_fdp(fdp) > 0:
                s = score_fdp(fdp)
                if fdp.name not in results or s > results[fdp.name][1]:
                    results[fdp.name] = (fdp, s)
                    print(f"    Found via syntax marker: {fdp.name} "
                          f"({len(fdp.message_type)} msgs, score {s})")
                break  # Found a valid parse for this marker

    return {n: fdp for n, (fdp, _) in results.items()}


# -- Strategy 3: Search for FileDescriptorSet ---------------------------------

def find_descriptor_set(data):
    """Try to find a serialized FileDescriptorSet blob."""
    # A FileDescriptorSet has field 1 (repeated FileDescriptorProto)
    # Each entry is: tag 0x0a + varint length + serialized FileDescriptorProto
    # The inner FileDescriptorProto also starts with 0x0a (its name field)
    # So we look for: 0x0a <outer_len> 0x0a <name_len> <ascii_string>
    results = {}
    i = 0
    tried = 0
    while i < len(data) - 20:
        if data[i] != 0x0a:
            i += 1
            continue
        outer_len, after_outer = read_varint(data, i + 1)
        if not outer_len or outer_len < 20 or outer_len > 524288:
            i += 1
            continue
        if after_outer >= len(data) or data[after_outer] != 0x0a:
            i += 1
            continue
        inner_len, after_inner = read_varint(data, after_outer + 1)
        if not inner_len or inner_len < 3 or inner_len > 300:
            i += 1
            continue
        if after_inner + inner_len > len(data):
            i += 1
            continue
        try:
            name = data[after_inner:after_inner + inner_len].decode('ascii')
        except (UnicodeDecodeError, ValueError):
            i += 1
            continue
        if not re.match(r'^[a-zA-Z0-9_/.\-]+$', name):
            i += 1
            continue

        # This looks like a FileDescriptorSet entry - try parsing the whole set
        tried += 1
        if tried > 200:
            break
        # Try parsing from offset i as a FileDescriptorSet
        for try_len in [outer_len + (after_outer - i) + 4096, 65536, 262144, 1048576]:
            end = min(i + try_len, len(data))
            chunk = data[i:end]
            fds = descriptor_pb2.FileDescriptorSet()
            try:
                fds.ParseFromString(chunk)
            except Exception:
                continue
            valid_files = [f for f in fds.file if f.name and score_fdp(f) > 0]
            if valid_files:
                for f in valid_files:
                    s = score_fdp(f)
                    if f.name not in results or s > results[f.name][1]:
                        results[f.name] = (f, s)
                print(f"    Found FileDescriptorSet at offset {i} with "
                      f"{len(valid_files)} valid file(s)")
                break
        i += 1

    print(f"  Strategy 3 (FileDescriptorSet): {len(results)} files found")
    return {n: fdp for n, (fdp, _) in results.items()}


# -- Common parsing helper ----------------------------------------------------

def try_parse_at_offsets(data, offsets):
    """Try to parse FileDescriptorProto at given (offset, name) pairs."""
    results = {}
    for idx, (offset, name) in enumerate(offsets):
        next_off = offsets[idx + 1][0] if idx + 1 < len(offsets) else len(data)
        gap = next_off - offset

        best, best_score = None, 0

        # Try the exact gap first (most likely to be correct boundary),
        # then try smaller sizes. Don't cap at 524KB since descriptors can be large.
        try_sizes = sorted(set([gap, gap // 2, gap // 4,
                                4096, 16384, 65536, 262144, 524288, 1048576]))
        for size in try_sizes:
            if size < 256 or size > gap:
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

        # Also accept score 0 if the FDP has a valid name, package, and syntax
        # (some proto files may only contain imports or options with no messages)
        if best is None and gap > 0:
            chunk = data[offset:offset + gap]
            fdp = descriptor_pb2.FileDescriptorProto()
            try:
                fdp.ParseFromString(chunk)
                if fdp.name == name and (fdp.message_type or fdp.enum_type or
                                          fdp.service or fdp.syntax):
                    best = descriptor_pb2.FileDescriptorProto()
                    best.CopyFrom(fdp)
                    best_score = max(score_fdp(fdp), 1)
            except Exception:
                pass

        if best and best_score > 0:
            prev = results.get(name)
            if not prev or best_score > prev[1]:
                results[name] = (best, best_score)
                print(f"    {name}: {len(best.message_type)} msgs, "
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

    for e in msg.enum_type:
        el = fmt_enum(e, lvl + 1)
        if el:
            lines.extend(el)
            lines.append('')

    for n in msg.nested_type:
        if not is_map_entry(n):
            ml = fmt_message(n, lvl + 1)
            if ml:
                lines.extend(ml)
                lines.append('')

    map_entries = {n.name: n for n in msg.nested_type if is_map_entry(n)}

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

    for f in msg.field:
        if f.number in written or not is_valid_ident(f.name):
            continue

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

    # Try all strategies and merge results
    all_descriptors = {}

    print('Strategy 1: Scanning for .proto name fields...')
    d1 = find_by_name_field(data)
    all_descriptors.update(d1)

    print('\nStrategy 2: Scanning for syntax markers...')
    d2 = find_by_syntax_marker(data)
    for name, fdp in d2.items():
        if name not in all_descriptors:
            all_descriptors[name] = fdp

    print('\nStrategy 3: Scanning for FileDescriptorSet...')
    d3 = find_descriptor_set(data)
    for name, fdp in d3.items():
        if name not in all_descriptors:
            all_descriptors[name] = fdp

    # Filter out google/protobuf well-known types (keep app-specific ones)
    app_descriptors = {n: f for n, f in all_descriptors.items()
                       if not n.startswith('google/')}
    google_descriptors = {n: f for n, f in all_descriptors.items()
                          if n.startswith('google/')}

    if google_descriptors:
        print(f'\nSkipping {len(google_descriptors)} google/protobuf standard types:')
        for name in sorted(google_descriptors):
            print(f'  {name}')

    if not all_descriptors:
        print('\nNo FileDescriptorProto blobs found by any strategy.')
        sys.exit(0)

    descriptors = app_descriptors if app_descriptors else all_descriptors

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
