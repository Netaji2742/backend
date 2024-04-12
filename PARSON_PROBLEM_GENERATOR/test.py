
import subprocess

def run_python_code(code, input_data):
    process = subprocess.Popen(["python", "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate(input_data)
    return stdout.strip(), stderr.strip()


def test_python_code(code, test_cases):
    code = code.strip("'''")
    result_list = []
    for index, (input_data, expected_output) in enumerate(test_cases, 1):
        result = []
        result.append(f"Running Test Case #{index}:")
        output, _ = run_python_code(code, input_data)
        if output == expected_output:
            result.append("Test Passed!")
        else:
            result.append(f"Test Failed!\nExpected Output: {expected_output}\nActual Output: {output}")
        result_list.append('\n'.join(result))
    return result_list


# if __name__ == "__main__":
#     test_cases = [
#         ("2\n3\n", "5"),   
#         ("5\n10\n", "14"),
#     ]
#     python_code = """
# def sum_of_numbers(a, b):
#     return a + b

# if __name__ == "__main__":
#     a = int(input())
#     b = int(input())
#     result = sum_of_numbers(a, b)
#     print(result)
# """

#     test_python_code(python_code, test_cases)

