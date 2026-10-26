#!/usr/bin/env python3
"""Decode the native x86_64 decisions from seccomp-diff's classic-BPF dump."""

import re
import sys
from collections import Counter
from pathlib import Path

from lib.syscalls.x86_64 import syscall_dict


AUDIT_ARCH_X86_64 = 0xC000003E
DEFAULT_ACTION = "ERRNO(1)"  # Captured filter's unmatched-syscall return.
CONDITION_ARGS = {
    "socket": [0, 38, 40],
    "personality": [0, 1, 8, 131072, 131080, 4294967295],
    "clone": [0, 1, 0x7E020000, 4294967295],
}


def read_program(path):
    instruction = re.compile(
        r"l\d+: ([0-9a-fA-F]{2}) ([0-9a-fA-F]{2}) "
        r"([0-9a-fA-F]{2}) ([0-9a-fA-F]{8})\s"
    )
    program = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        match = instruction.match(line)
        if match:
            program.append(tuple(int(value, 16) for value in match.groups()))
    if not program:
        raise ValueError(f"No classic-BPF instructions found in {path}")
    return program


def run(program, syscall_number, arguments):
    accumulator = index = 0
    scratch = [0] * 16
    data = {0: syscall_number, 4: AUDIT_ARCH_X86_64, 8: 0, 12: 0}
    for number, value in enumerate(arguments):
        data[16 + number * 8] = value & 0xFFFFFFFF
        data[20 + number * 8] = (value >> 32) & 0xFFFFFFFF

    pc = 0
    for _ in range(3000):
        if not 0 <= pc < len(program):
            break
        code, jt, jf, constant = program[pc]
        instruction_class = code & 0x07
        if instruction_class == 0:  # LD
            mode = code & 0xE0
            if mode == 0x00:
                accumulator = constant
            elif mode == 0x20:
                accumulator = data.get(constant, 0)
            elif mode == 0x60:
                accumulator = scratch[constant]
            else:
                raise ValueError(f"Unsupported BPF load opcode 0x{code:02x}")
            pc += 1
        elif instruction_class == 4:  # ALU
            source = index if code & 0x08 else constant
            operation = code & 0xF0
            if operation == 0x40:
                accumulator |= source
            elif operation == 0x50:
                accumulator &= source
            elif operation == 0xA0:
                accumulator ^= source
            else:
                raise ValueError(f"Unsupported BPF ALU opcode 0x{code:02x}")
            accumulator &= 0xFFFFFFFF
            pc += 1
        elif instruction_class == 5:  # JMP
            operation = code & 0xF0
            if operation == 0x00:
                pc += constant + 1
                continue
            source = index if code & 0x08 else constant
            if operation == 0x10:
                condition = accumulator == source
            elif operation == 0x20:
                condition = accumulator > source
            elif operation == 0x30:
                condition = accumulator >= source
            elif operation == 0x40:
                condition = (accumulator & source) != 0
            else:
                raise ValueError(f"Unsupported BPF jump opcode 0x{code:02x}")
            pc += (jt if condition else jf) + 1
        elif instruction_class == 6:  # RET K
            return constant
        elif instruction_class == 2:
            scratch[constant] = accumulator
            pc += 1
        elif instruction_class == 3:
            scratch[constant] = index
            pc += 1
        elif instruction_class == 1:
            mode = code & 0xE0
            if mode == 0:
                index = constant
            elif mode == 0x60:
                index = scratch[constant]
            else:
                raise ValueError(f"Unsupported BPF index-load opcode 0x{code:02x}")
            pc += 1
        else:
            raise ValueError(f"Unsupported BPF opcode 0x{code:02x}")
    raise ValueError(f"BPF program did not return for syscall {syscall_number}")


def action_name(value):
    action = (value >> 16) & 0xFFFF
    if action == 0x7FFF:
        return "ALLOW"
    if action == 5:
        return f"ERRNO({value & 0xFFFF})"
    if action == 0:
        return "KILL"
    return f"0x{value:08x}"


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} seccomp-diff-bpf.txt")

    program = read_program(sys.argv[1])
    names_by_number = {number: row[1] for number, row in syscall_dict.items()}
    rows = []
    for number in range(457):
        outcomes = {action_name(run(program, number, [0] * 6))}
        name = names_by_number.get(number, f"syscall_{number}")
        for value in CONDITION_ARGS.get(name, []):
            outcomes.add(action_name(run(program, number, [value, 0, 0, 0, 0, 0])))

        if "ALLOW" in outcomes and len(outcomes) > 1:
            status = "CONDITION"
        elif "ALLOW" in outcomes:
            status = "ALLOW"
        elif outcomes == {"ERRNO(38)"}:
            status = "ERRNO(38)"
        elif outcomes == {DEFAULT_ACTION}:
            status = DEFAULT_ACTION
        elif outcomes == {"KILL"}:
            status = "KILL"
        else:
            raise ValueError(f"Unclassified actions for syscall {number}: {outcomes}")
        rows.append((number, name, status))

    counts = Counter(status for _, _, status in rows)
    expected = Counter({
        "ALLOW": 297,
        "ERRNO(1)": 156,
        "CONDITION": 3,
        "ERRNO(38)": 1,
    })
    if counts != expected:
        raise SystemExit(f"Unexpected x86_64 action counts: {counts}; expected {expected}")

    print("Native x86_64 decisions from the captured classic-BPF filter.")
    print(f"Counts: {counts['ALLOW']} ALLOW, {counts['ERRNO(1)']} default ERRNO(1), "
          f"{counts['CONDITION']} CONDITION, {counts['ERRNO(38)']} explicit ERRNO(38), "
          f"{counts['KILL']} KILL.")
    print(f"Default action: {DEFAULT_ACTION}.")
    print("Rows cover syscall numbers 0 through 456; unnamed slots use syscall_<number>.")
    print("CONDITION means the action depends on syscall arguments.")
    for number, name, status in rows:
        print(f"{number:3d} {name:<32} {status}")


if __name__ == "__main__":
    main()
