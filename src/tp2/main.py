from src.tp2.utils.lib import disassemble
from src.tp2.utils.llm import AnalyzeShellcode
import os

def main():
    # Check if the shellcode file exists
    shellcode_file = os.path.join(os.path.dirname(__file__), "utils", "shellcode.bin")
    if not os.path.exists(shellcode_file):
        print(f"Shellcode file '{shellcode_file}' not found.")
        return

    # Read the shellcode from the file
    with open(shellcode_file, "rb") as f:
        shellcode = f.read()

    # Disassemble the shellcode
    disassemble(shellcode)

    # Analyze the shellcode using the LLM
    analysis_result = AnalyzeShellcode(shellcode)
    print(analysis_result)

if __name__ == "__main__":
    main()
