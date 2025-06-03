import textwrap
import sys
from pylibemu import Emulator # type: ignore
from capstone import Cs, CS_ARCH_X86, CS_MODE_32 # type: ignore

def analyze_shellcode(shellcode):
    # Génération du hexdump
    hex_data = " ".join(f"{byte:02x}" for byte in shellcode)
    hex_str = textwrap.fill(hex_data, width=80)
    hexdump_section = f"Hexdump:\n{hex_str}"

    # Désassemblage avec Capstone
    disassembly = []
    try:

        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for insn in md.disasm(shellcode, 0x1000):
            disassembly.append(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
    except ImportError:
        disassembly = ["Capstone non installé. Veuillez installer pycapstone."]
    except Exception as e:
        disassembly = [f"Erreur de désassemblage: {str(e)}"]

    # Émulation avec pylibemu
    emulation_results = {"warnings": [], "api_calls": []}
    try:
        emulator = Emulator()
        offset = emulator.prepare(shellcode, 0)
        
        try:
            result = emulator.run(0) 
            emulation_results["emulation_result"] = f"Terminé à l'offset: 0x{result:x}"
            
            # Détection d'appels système (exemple basique)
            if emulator.shellcode:
                emulation_results["shellcode_detected"] = True
                sc = emulator.shellcode
                emulation_results["api_calls"] = [
                    f"Appel à {call.name} (0x{call.address:x})" 
                    for call in sc.calls
                ]
            else:
                emulation_results["shellcode_detected"] = False
                
        except Exception as e:
            emulation_results["warnings"].append(f"Émulation échouée: {str(e)}")

    except ImportError:
        emulation_results["warnings"].append("pylibemu non installé. Installer pylibemu pour l'analyse dynamique.")

    # Construction du rapport
    report = [
        "---------------- Analyse de Shellcode ----------------",
        hexdump_section,
        "\nDésassemblage:",
        "\n".join(disassembly) if disassembly else "Aucun résultat",
        "\nRésultats d'émulation:",
        f"- Statut: {emulation_results.get('emulation_result', 'Non exécuté')}",
        f"- Shellcode détecté: {emulation_results.get('shellcode_detected', 'Inconnu')}",
        "- API/System calls détectés:" if emulation_results["api_calls"] else "Aucun appel détecté",
        *[f"  • {call}" for call in emulation_results["api_calls"]],
        *[f"⚠ {warn}" for warn in emulation_results["warnings"]]
    ]

    return "\n".join(report)

