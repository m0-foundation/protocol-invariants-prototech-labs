#!/usr/bin/env bash

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
