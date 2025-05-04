import os
import re
import shutil
import argparse
from pathlib import Path


def create_starter_code(crate_path):
    # Resolve the absolute path and validate the crate directory
    crate_path = Path(crate_path).resolve()
    if not crate_path.is_dir():
        raise ValueError(
            f"The provided path '{
                crate_path}' is not a valid directory."
        )

    # Get the crate name and create the new directory name
    crate_name = crate_path.name
    starter_crate_name = f"{crate_name}-starter-code"
    starter_crate_path = crate_path.parent / starter_crate_name

    # Copy the crate to the new directory, excluding .git and target directories
    if starter_crate_path.exists():
        shutil.rmtree(starter_crate_path)
    shutil.copytree(
        crate_path, starter_crate_path, ignore=shutil.ignore_patterns(".git", "target")
    )

    # Process each file in the new directory
    for root, _, files in os.walk(starter_crate_path):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith(".rs"):  # Only process Rust source files
                process_file(file_path)

    print(f"Starter code created at: {starter_crate_path}")


def process_file(file_path):
    with open(file_path, "r") as f:
        lines = f.readlines()

    # Process the lines to replace solution blocks
    new_lines = []
    inside_solution = False

    for line in lines:
        if line.strip() == "// BEGIN SOLUTION":
            inside_solution = True
        elif line.strip() == "// END SOLUTION":
            inside_solution = False
        elif inside_solution:
            # Process only lines starting with `// TODO:`
            if line.strip().startswith("// TODO:"):
                indent = line[: line.index("// TODO:")]
                todo_string = line.strip().replace("// ", "").strip()
                # Add the TODO comment and unimplemented! macro
                new_lines.append(line)
                new_lines.append(f'{indent}unimplemented!("{todo_string}");\n')
            # Process only lines starting with `// TODO:`
            if line.strip().startswith("// HINT:"):
                # Add the HINT comment
                new_lines.append(line)
        else:
            new_lines.append(line)

    # Write the modified lines back to the file
    with open(file_path, "w") as f:
        f.writelines(new_lines)


def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(
        description="Generate starter code from a Rust crate."
    )
    parser.add_argument("crate_path", help="Path to the Rust crate directory.")
    args = parser.parse_args()

    try:
        create_starter_code(args.crate_path)
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
