import os
import sys
from src.tp2.utils.analyze import analyze_with_pylibemu

def main():
    shellcode_file = os.path.join(os.path.dirname(__file__), "utils", "shellcode.bin")
    if not os.path.exists(shellcode_file):
        print(f"Shellcode file '{shellcode_file}' not found.")
        sys.exit(1)

    result = analyze_with_pylibemu(shellcode_file)
    # Ici on imprime le résultat renvoyé par la fonction
    print(f"Execution result:\n{result}")

if __name__ == "__main__":
    main()
