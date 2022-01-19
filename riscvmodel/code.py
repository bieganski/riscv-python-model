import argparse
from tempfile import mkstemp
import subprocess

from .insn import *
from . import __version__

class MachineDecodeError(Exception):
    def __init__(self, word):
        self.word = word
    def __str__(self):
        return "Invalid instruction word: {:08x}".format(self.word)

def decode(word: int, variant: Variant=RV32I):
    if word & 0x3 != 3:
        # compact
        for icls in get_insns(cls=InstructionCType):
            if icls._match(word):
                i = icls()
                i.decode(word)
                return i
        raise MachineDecodeError(word)
    opcode = word & 0x7F
    variants = [
        Variant("RV32I"),
        Variant("RV32E"),
        Variant("RV32IZicsr"),
        Variant("RV32IZifencei"),
        Variant("RV32IM"),
        Variant("RV32IC"),
        Variant("RV64I"),
        Variant("RV64G"),
        Variant("RV64GC"),
        Variant("RV128I"),
        Variant("RV32A"),
    ]
    
    for variant in variants:
        results = []
        for icls in get_insns(variant=variant):
            if icls.field_opcode.value == opcode and icls.match(word):
                i = icls()
                # i.decode(word)
                results.append(i)
        if len(results) == 1:
            i = results[0]
            i.decode(word)
            return i
        elif len(results) == 0:
            continue
        else:
            # csr - match by immediate (which is not static_field..)
            opcode = i.extract_field("opcode", word)
            if opcode != 0b1110011: # not system
                # we need that crappy check as it fails e.g. for [addi, nop]...
                i = results[0]
                i.decode(word)
                return i
            my_immediate = i.extract_field("imm", word)
            for i in results:
                imm_val = [field.value for field in i.get_fields() if field.name == "imm"][0]
                if imm_val == my_immediate:
                    i.decode(word)
                    return i
    raise MachineDecodeError(word)

def read_from_binary(fname: str, *, stoponerror: bool = False):
    with open(fname, "rb") as f:
        insn = f.read(4)
        while insn:
            try:
                yield decode(int.from_bytes(insn, 'little'))
            except MachineDecodeError as e:
                if stoponerror:
                    return
                raise(e)
            insn = f.read(4)

def machinsn_decode():
    parser = argparse.ArgumentParser(description='Disassemble a machine instruction.')
    parser.add_argument('--version', help='Display version', action='version', version=__version__)
    subparsers = parser.add_subparsers()
    parser_cmdline = subparsers.add_parser('hexstring', help='From commandline hexstrings')
    parser_cmdline.add_argument('insn', type=str, nargs='+', help='Instruction(s) as hexstring (0x...)')
    parser_file = subparsers.add_parser('objfile', help='Read from object file')
    parser_file.add_argument('filename', type=str, help='Filename')
    parser.add_argument('--objcopy', type=str, default="riscv32-unknown-elf-objcopy", help='objcopy executable')
    args = parser.parse_args()

    if "insn" in args:
        for i in args.insn:
            try:
                print(decode(int(i,16)))
            except MachineDecodeError:
                print("Cannot decode {:08x}, invalid instruction".format(int(i,16)))
    elif "filename" in args:
        temp = mkstemp(suffix='.bin')
        subprocess.call([args.objcopy, '-O', 'binary', args.filename, temp[1]])

        for i in read_from_binary(temp[1]):
            print(i)
    else:
        parser.print_help()
