import random
import tokenize
from io import BytesIO


def divide_python_code_into_blocks(python_code):
    blocks = []
    current_block = []
    current_indentation = 0

    for line in python_code.split('\n'):
        line_stripped = line.strip()
        if not line_stripped:
            continue
        if line_stripped.startswith(("#", "'''")):
            continue

        # Strip leading spaces or tabs
        line_stripped = line.lstrip()

        # Check for different block types
        if line_stripped.startswith(("def ", "class ", "for ", "if ", "elif ", "else:", "try:", "except ", "finally:", "while ")):
            if current_block:
                blocks.append(current_block)
            current_block = [line_stripped]
            # Set the current indentation level based on the first line of the new block
            current_indentation = len(line) - len(line.lstrip())
        else:
            # Calculate indentation for the current line
            indentation = len(line) - len(line.lstrip())
            # Check if the indentation level matches the current block
            if indentation > current_indentation:
                current_block.append(line_stripped)
            else:
                # Start a new block
                if current_block:
                    blocks.append(current_block)
                current_block = [line_stripped]
                # Update the current indentation level
                current_indentation = indentation

    # Append the last block
    if current_block:
        blocks.append(current_block)

    return blocks
