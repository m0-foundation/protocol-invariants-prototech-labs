#!/usr/bin/env python3

import os
import re

def remove_ansi_colors(text):
    # Regular expression to match ANSI color codes
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def clean_log_files(directory):
    for filename in os.listdir(directory):
        if filename.endswith(".log"):
            file_path = os.path.join(directory, filename)

            # Read the file
            with open(file_path, 'r') as file:
                content = file.read()

            # Clean the content
            cleaned_content = remove_ansi_colors(content)

            # Write the cleaned content back
            with open(file_path, 'w') as file:
                file.write(cleaned_content)
            print(f"Cleaned {filename}")

# Specify your directory here
directory = './logs'
clean_log_files(directory)
