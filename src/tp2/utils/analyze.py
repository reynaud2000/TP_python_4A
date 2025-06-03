from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL, UC_HOOK_CODE
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import textwrap
from pathlib import Path
from typing import Union

# ... votre load_shellcode_bin et votre table SYM ...

def analyze_shellcode(input_bin: Union[str, Path]) -> str:
    # 1) et 2) chargement + hexdump
    sc = load_shellcode_bin(input_bin)
    # 3) désassemblage statique
    disasm = [f"0x{ins.address:04x}: {ins.mnemonic:8} {ins.op_str}"
              for ins in Cs(CS_ARCH_X86, CS_MODE_32).disasm(sc, 0x1000)]

    # 4) émulation
    BASE, STACK_BASE, STACK_SIZE = 0x1000, 0x200000, 0x10000
    MAX_STEPS = 5000
    api_calls, errors = [], []

    try:
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        # map shellcode
        size_map = 0x1000*((len(sc)//0x1000)+1)
        uc.mem_map(BASE, size_map, UC_PROT_ALL)
        uc.mem_write(BASE, sc)
        # map stack
        uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
        uc.reg_write(UC_X86_REG_ESP, STACK_BASE + STACK_SIZE//2)

        # stubs RET pour chaque API fictive
        for addr in SYM:
            page = addr & ~0xfff
            uc.mem_map(page, 0x1000, UC_PROT_ALL)
            uc.mem_write(addr, b"\xC3")

        # hook sur chaque instruction
        def hook_code(uc_engine, address, size, user_data):
            code = uc_engine.mem_read(address, size)
            for insn in Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, address):
                if insn.mnemonic == "call":
                    target = None
                    op = insn.op_str
                    if op.startswith("0x"):
                        try: target = int(op, 16)
                        except: pass
                    else:
                        reg = getattr(unicorn, f"UC_X86_REG_{op.upper()}", None)
                        if reg is not None:
                            target = uc_engine.reg_read(reg)
                    if target in SYM:
                        api_calls.append(f"{SYM[target]} @{hex(address)}")

        uc.hook_add(UC_HOOK_CODE, hook_code)

        uc.emu_start(BASE, BASE + len(sc), timeout=0, count=MAX_STEPS)

    except Exception as e:
        errors.append(f"Émulation Unicorn interrompue: {e!s}")

    # 5) rapport final
    report = [f"=== Analyse de {Path(input_bin).name} ===", *hexdump,
              "\n[CAPSTONE] Instructions désassemblées:"]
    report += disasm
    report.append("\n[UNICORN] API calls détectées (émulation pas-à-pas):")
    if api_calls:
        report += [f"• {c}" for c in api_calls]
    else:
        report.append("Aucune détection")
    for e in errors:
        report.append("⚠ " + e)

    return "\n".join(report)
