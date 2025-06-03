import textwrap
from pathlib import Path
from typing import Union
from pylibemu import Emulator
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

def load_shellcode_bin(input_path: Union[str, Path]) -> bytes:
    path = Path(input_path)
    if path.suffix != ".bin":
        raise ValueError("Seuls les .bin sont acceptés")
    if not path.exists():
        raise FileNotFoundError(f"{path} introuvable")
    return path.read_bytes()

def analyze_shellcode(input_bin: Union[str, Path]) -> str:
    # 1) chargement du binaire
    try:
        sc_bytes = load_shellcode_bin(input_bin)
    except Exception as e:
        return f"ERREUR: {e!s}"

    # 2) hexdump
    hexdump = [
        f"Hexdump ({len(sc_bytes)} octets):",
        textwrap.fill(" ".join(f"{b:02x}" for b in sc_bytes), width=80)
    ]

    # 3) désassemblage statique
    disasm = []
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    for insn in cs.disasm(sc_bytes, 0x1000):
        disasm.append(f"0x{insn.address:04x}: {insn.mnemonic:8} {insn.op_str}")

    # 4) émulation pas-à-pas + hook "CALL"
    emu = Emulator()
    BASE = 0x1000
    ret = emu.prepare(sc_bytes, BASE)
    api_calls = []
    errors    = []
    MAX_STEPS = 5000

    if isinstance(ret, int) and ret != 0:
        errors.append(f"emu.prepare a retourné {ret}")
    else:
        # 4.a) table d'API fictives (adresses hors du shellcode)
        SYM = {
            0x7C810000: "LoadLibraryA",
            0x7C820000: "GetProcAddress",
            0x7C830000: "URLDownloadToFileA",
            0x7C840000: "WinExec",
            0x7C850000: "CreateProcessA",
        }

        # 4.b) boucle pas-à-pas
        cs_run = Cs(CS_ARCH_X86, CS_MODE_32)
        pc     = BASE
        step   = 0

        try:
            while step < MAX_STEPS:
                # fetch+désasm depuis sc_bytes
                off = pc - BASE
                if off < 0 or off >= len(sc_bytes):
                    errors.append(f"EIP hors shellcode: {hex(pc)} – arrêt")
                    break
                code = sc_bytes[off : off + 16]
                insns = list(cs_run.disasm(code, pc, count=1))
                if not insns:
                    errors.append(f"Impossible de désassembler à {hex(pc)}")
                    break
                ins = insns[0]

                # si c'est un CALL, on essaie de résoudre l'opérande
                if ins.mnemonic == "call":
                    op = ins.op_str.strip()
                    target = None
                    # call imm
                    if op.startswith("0x"):
                        try:
                            target = int(op, 16)
                        except ValueError:
                            pass
                    # call reg
                    elif op in ("eax","ebx","ecx","edx","esi","edi","esp","ebp"):
                        try:
                            target = emu.get_register(op.upper())
                        except Exception:
                            pass

                    # si dans notre table, c'est un API
                    if target in SYM:
                        api_calls.append(f"{SYM[target]} @{hex(ins.address)}")

                # on exécute l'instruction suivante
                r = emu.step()
                # r != 0 ➔ plantage ou fin
                if r != 0:
                    errors.append(f"emu.step() a retourné {r} – arrêt")
                    break

                # on récupère le nouveau EIP
                try:
                    pc = emu.get_register("EIP")
                except Exception as e:
                    errors.append(f"get_register(EIP) a levé {e}")
                    break

                step += 1

        except Exception as e:
            errors.append(f"Emulation interrompue: {e!s}")

    # 5) construction du rapport
    report = [f"=== Analyse de {Path(input_bin).name} ===", *hexdump,
              "\n[CAPSTONE] Instructions désassemblées:"]
    report += disasm
    report.append("\n[HOOK-SHELL] API calls détectées (pas-à-pas):")
    if api_calls:
        report += [f"• {c}" for c in api_calls]
    else:
        report.append("Aucune détection")
    for e in errors:
        report.append(f"⚠ {e}")

    return "\n".join(report)
