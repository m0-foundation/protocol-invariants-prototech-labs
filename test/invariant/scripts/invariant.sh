#!/usr/bin/env bash

# // SPDX-FileCopyrightText: © 2024 Prototech Labs <info@prototechlabs.dev>
# // SPDX-License-Identifier: AGPL-3.0-or-later
# //
# // Copyright © 2024 Christopher Mooney
# // Copyright © 2024 Chris Smith
# // Copyright © 2024 Brian McMichael
# // Copyright © 2024 Derek Flossman
# //
# // This program is free software: you can redistribute it and/or modify
# // it under the terms of the GNU Affero General Public License as published by
# // the Free Software Foundation, either version 3 of the License, or
# // (at your option) any later version.
# //
# // This program is distributed in the hope that it will be useful,
# // but WITHOUT ANY WARRANTY; without even the implied warranty of
# // MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# // You should have received a copy of the GNU Affero General Public License
# // along with this program.  If not, see <https://www.gnu.org/licenses/>.


nc_set=false

# Parse command-line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --runs=*)  runs="${1#*=}"  ;;
        --depth=*) depth="${1#*=}" ;;
        --v=*)     v="${1#*=}"     ;;
        --mt=*)    mt="${1#*=}"    ;;
        --mc=*)    mc="${1#*=}"    ;;
          nc)      nc_set=true     ;;
        --type=*)  type="${1#*=}"  ;;
        --seed=*)  seed="${1#*=}"  ;;
        --leap=*)  leap="${1#*=}"  ;;
        *) echo "Unknown parameter passed: $1"; exit 1;;
    esac
    shift
done

if [ -n "$runs" ]; then
    export FOUNDRY_INVARIANT_RUNS="$runs"
fi

if [ -n "$depth" ]; then
    export FOUNDRY_INVARIANT_DEPTH="$depth"
fi

vstr=""
if [ -n "$v" ]; then
    for (( i=0; i<$v; i++ ))
    do
        vstr+="v"
    done
    if [[ ! -z $vstr ]]; then
        vstr="-$vstr"
    fi
fi

mcstr=""
if [ -n "$mc" ]; then
  mcstr="--mc $mc"
fi

mtstr="--mt invariant"
if [ -n "$mt" ]; then
  mtstr="--mt $mt"
fi

if [ -z "$seed" ]; then
    seed=$(shuf -i 1-18446744073709551615 -n 1)
fi

seedstr="--fuzz-seed $seed"

if [ -n "$leap" ]; then
    export MAX_LEAP="$leap"
fi

if [ "$nc_set" == false ]; then
    forge clean
fi

echo "Running ${type} tests"
test_data="Runs: ${runs:-"default"}, Depth: ${depth:-"default"}, v: ${vstr:-"none"}, mt: ${mt:-"invariant"}, mc: ${mc:-"all"}, leap: ${MAX_LEAP:-default}, nc: ${nc_set}, fuzz-seed: ${seed}"

echo "$test_data"

runfile="./logs/$(date +%Y%m%d%H%M%S)-invariant-${seed}.log"

if [ "$type" == "invariant" ]; then
    nmcstr="--nmc RegressionTests"
    mkdir -p ./out
    output=$(echo "$test_data"; forge test $mtstr $nmcstr $vstr $mcstr $seedstr;)
    echo "$output" | tee ./out/sequence.log
    # Strip ANSI color codes for the condition check
    clean_output=$(echo "$output" | sed 's/\x1b\[[0-9;]*m//g')

    # Conditionally write to $runfile if the output contains "Test result: FAIL"
    if echo "$clean_output" | grep -q "Test result: FAIL"; then
        echo "$output" | tee $runfile
    fi
fi

if [ "$type" == "regression" ]; then
    forge test $mtstr $nmcstr $vstr $mcstr $seedstr
fi
