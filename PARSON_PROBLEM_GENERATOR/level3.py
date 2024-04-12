import random
import tokenize
from io import BytesIO

def tokenize_python_code_block(python_code_block):
    tokens = []
    filtered_tokens = []
    
    code_bytes = bytes(python_code_block, 'utf-8')
    for token in tokenize.tokenize(BytesIO(code_bytes).readline):
        # Skip adding empty strings and 'utf-8' to the list of tokens
        if token.string and token.string != 'utf-8':
            # print(token)
            tokens.append(token.string)
        if token.string and token.string != 'utf-8' and token.type != tokenize.INDENT and token.type != tokenize.DEDENT and token.type != tokenize.NEWLINE and token.type != tokenize.STRING and token.string != '(' and token.string != ')' and token.string != ':' and token.string != ',':
            filtered_tokens.append(token.string)

    index = random.randint(0, len(filtered_tokens) - 1)
    # Get the selected token from the filtered list
    selected_token = filtered_tokens[index]

    # Replace the selected token with dashes in the original list of tokens
    modified_code = ''
    for i, token in enumerate(tokens):
        if token == '\n':
            modified_code += tokens[i]
        elif token == selected_token:
            tokens[i] = '___'
            modified_code += " " + tokens[i]
        else:
            modified_code += " " + tokens[i]

    # Split modified_code into lines, apply lstrip() to each line, and join them back together
    modified_code = '\n'.join(line.lstrip() for line in modified_code.splitlines())

    return modified_code

    
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

