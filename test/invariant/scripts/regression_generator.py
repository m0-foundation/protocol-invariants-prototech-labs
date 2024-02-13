#!/usr/bin/env python3

import re
import hashlib
import sys

 # Default filename
default_filename = './out/sequence.log'

# Check if filename is provided as a command-line argument
filename = sys.argv[1] if len(sys.argv) > 1 else default_filename

def remove_ansi_escape_sequences(text):
    ansi_escape_pattern = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape_pattern.sub('', text)

with open(filename, 'r') as f:
    formatted_text = f.read()

clean_text = remove_ansi_escape_sequences(formatted_text)

maxLeap = clean_text.split("leap: ")[1].split(',')[0]
if maxLeap == "default":
    maxLeap = "43200"   # 12 hours

# get the regression name from the invariant file
failures = clean_text.split("Failing tests:")[1]
# parse the different regression sets we have
regressionTests = failures.split("Encountered")[1:-1]
regressions = {}
for lines in regressionTests:
    regressionName = lines.split("/")[2].split("Invariants")[0] + "Regressions.t.sol"

    sequences = lines.split("[Sequence]")
    for sequence in sequences:
        lines = sequence.splitlines()
        lines = [line for line in lines if "Depth:" in line or "sender" in line or "invariant_" in line]
        seq_output = []
        test_handler = ""
        for line in lines:
            if "sender" in line:
                first_line = line
                full_handler = first_line.split("addr=[")[1].split(']')[0].split(":")[1]
                handler_prefix = '_' + ''.join(full_handler[:1].lower())
                handler_suffix = full_handler[1:]
                test_handler = handler_prefix + handler_suffix
                function_name = line.split("calldata=")[1].split('(')[0]
                args = line.split("args=")[1][1:-1]
                args = "(" + args + ")"
                args = re.sub(r"(\s\[\d(\.\d{0,3})?e\d+\])", "", args)
                sequence_call = function_name + args + ";"
                seq_output.append('        ' + test_handler + '.' + ''.join(sequence_call.splitlines()))
            elif "invariant_" in line:
                invariant = line.split("invariant_")[1].split('(')[0]
                hash_string = ''.join(lines[0:lines.index(line)])
                hash_value = hashlib.sha256(hash_string.encode()).hexdigest()
                seq_output.insert(0, '')
                seq_output.insert(1, '    function test_regression_invariant_' + invariant + '_' + hash_value[:8] + '_failure() external {')
                seq_output.insert(2, '        _setMaxLeap(' + maxLeap + ');')
                seq_output.append('')
                seq_output.append('        invariant_' + invariant + '();')
                seq_output.append('    }')
                if regressionName in regressions:
                    regressions[regressionName].append(seq_output)
                else:
                    regressions[regressionName] = [seq_output]

for regression, tests in regressions.items():
    file_path = './test/invariant/regressions/'+regression
    with open(file_path, 'r') as file:
        content = file.read()

    last_bracket_position = content.rfind('}')

    if last_bracket_position == -1:
        print("No closing bracket found.")
        break

    print("// Adding new tests to " + regression)
    string_tests = []
    for test in tests:
        string_tests.append('\n'.join(test))

    for test in string_tests:
        print(test)

    new_content = content[:last_bracket_position] + '\n'.join(string_tests) + '\n' + content[last_bracket_position:]

    with open(file_path, 'w') as file:
        file.write(new_content)

print("\n\n\n============== Added Regressions to the following files: ==============")
for regression, tests in regressions.items():
    print(regression)
