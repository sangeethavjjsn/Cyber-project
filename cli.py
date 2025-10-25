import sys
import json
import os
from analyzer import SecurityAnalyzer

def main():
    if len(sys.argv) < 2:
        print("Usage: python cli.py <file> [--out <output.json>]")
        return
    
    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"❌ File not found: {filepath}")
        return

    # Detect file type
    if filepath.endswith(".php"):
        file_type = "php"
    elif filepath.endswith(".js"):
        file_type = "js"
    else:
        print("❌ Unsupported file type. Use PHP or JS.")
        return

    # Read file content
    with open(filepath, "r", encoding="utf-8") as f:
        code_content = f.read()

    analyzer = SecurityAnalyzer()
    results = analyzer.analyze_code(code_content, file_type)

    # Check if output file is provided
    if "--out" in sys.argv:
        out_index = sys.argv.index("--out") + 1
        if out_index < len(sys.argv):
            output_file = sys.argv[out_index]
            with open(output_file, "w", encoding="utf-8") as out:
                json.dump(results, out, indent=4)
            print(f"✅ Report saved to {output_file}")
            return

    # Default: just print JSON to console
    print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()
