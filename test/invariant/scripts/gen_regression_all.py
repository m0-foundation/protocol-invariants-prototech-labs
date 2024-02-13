#!/usr/bin/env python3

import os
import subprocess

def gen_regressions(directory):
    for filename in os.listdir(directory):
        if filename.endswith(".log"):
            file_path = os.path.join(directory, filename)

            command = ['python3', './test/invariant/scripts/regression_generator.py', file_path]
            subprocess.run(command)


# Specify your directory here
directory = './logs'
gen_regressions(directory)
