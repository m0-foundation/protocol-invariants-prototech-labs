#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2024 Prototech Labs <info@prototechlabs.dev>
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright © 2024 Christopher Mooney
# Copyright © 2024 Chris Smith
# Copyright © 2024 Brian McMichael
# Copyright © 2024 Derek Flossman
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
