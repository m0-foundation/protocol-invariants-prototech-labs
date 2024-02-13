# M^0 Protocol Invariant Tests

Originally developed by [Prototech Labs](https://www.prototechlabs.dev/) for the M^0 core team, this repository contains a comprehensive suite of stateful fuzzing invariant tests, specifically designed for the M^0 protocol. These tests are meticulously crafted with the primary objective of uncovering any potential defects and vulnerabilities within the M^0 protocol. The strategic approach employed in these tests involves encapsulating the core protocol interfaces within specialized handlers. These handlers are then subjected to randomized calls, with the inputs strategically bounded to values that effectively probe the most critical branching paths in the codebase. This methodical process is not just a mere exercise in testing but a robust investigation into the resilience and reliability of the protocol.

In addition to the initial uncovering of defects, this repository plays a pivotal role in the ongoing maintenance and enhancement of the M^0 protocol. Through continuous and rigorous testing, it aims to preemptively identify and address any vulnerabilities that might emerge over time. This proactive approach is crucial in maintaining the integrity of the protocol. The repository serves as an early warning system, ensuring that potential defects are identified and mitigated before they can be exploited in a real-world scenario. This is not just a measure of precaution but a testament to M^0's commitment to security.

## Install dependencies

```bash
 forge install
```

To compile the contracts

```bash
 make
```

## Tests

There are two main types of tests available: **Invariant Tests** and **Regression Tests**.

### Invariant Tests

Invariant tests are used to perform a stateful fuzzing campaign.  One can specify how much `depth` to maintain state for, and even how many `runs` to perform at that depth.  Another useful configuration option is how much random time to warp ahead by between calls, which can surface defects on both small and larger timescales.  A random starting `seed` is used for all test runs, which makes the particular campaign reproducible.  This is extremely useful for debugging during development, where a test may hang, a regression may fail to reproduce the failure, or one wants to compare the results on different versions of foundry.  Occasionally one may also want to use the same `seed` to resolve an interesting regression and see how the campaign would have finished if a defect or error in the handler or invariant was resolved.

To do a single invariant run with defaults simply type:

```bash
 make invariant
```

This will compile and run invariant tests with the following values as defaults.  These values are chosen to accommodate rapid/accurate development, and we strongly suggest changing these for longer running campaigns.
```bash
Runs: 2            # good to ensure multiple runs can happen
Depth: 200         # depth that allows for a rapid development process
v: 1               # verbosity level
mt: invariant      # the invariant name to match (all invariants start with invariant_)
mc: all            # the contract name to match
leap: 43200        # when warping time forward, a random value between 0 and 43200 (12 hours) will be chosen
nc: false          # by default, we always compile again
fuzz-seed: N       # this will print the fuzz seed for this run
```

So, if we wanted to run a `10` run campaign with `500` depth we would type:
```bash
make invariant runs=10 depth=500
```

Often, we don't want this command to compile every time.  If the above command was successful and we wanted to do another test, we could run it again without having to wait for the compile with:
```bash
make invariant-nc runs=10 depth=500
```

Sometimes we may be interested in drilling down on a specific set of invariant tests, like all of the invariant tests in `MTokenInvariants`.  This can be used to test MToken's invariants with it's underlying components made up of mocks.  The advantage here is to explore at a greater depth.  For example, the following performs `1` run, at a state depth of `2500` calls, but will only target invariants in the `MTokenInvariants` file:
```bash
make invariant runs=1 depth=2500 mc=MTokenInvariants
```

Similarly, we could target the `ProtocolInvariants`, using a deploy of `MToken` and `MinterGateway`, but a mock of the `Registry` with:
```bash
make invariant runs=1 depth=2000 mc=ProtocolInvariants
```

The same can be done for a deploy of `TTG` by running just the `TTGInvariants` with:
```bash
make invariant runs=1 depth=2000 mc=TTGInvariants
```

And, finally, one can test a fully deployed and integrated M^0 protocol with:
```bash
make invariant runs=1 depth=1500 mc=MZeroInvariants
```

We've also included a powerful utility that allows one to run long `overnight` campaigns where any errors that surface will be durably written to the `./logs` directory.
```bash
make overnight
```

This command can also be combined with any of the above flags for a more fine tuned campaign:
```bash
make overnight runs=1 depth=1500 mc=MZeroInvariants
```

### Regression Tests

If an invariant violation is found, or if an uncaught error is surfaced, it will produce a log file in `./out`, which will be replaced from campaign to campaign, as well as a more durable log file in the `./logs` directory.  These logs will contain one or more `Sequence` sections that can be evaluated.  Unfortunately, this raw log is difficult to read, especially for deep call stacks, so we've included a helpful command that one can run to extract the exact set of calls that reproduce the failure, and write them into their respective regression files located in the `./test/invariant/regressions` directory.

```bash
make gen-regression
```

In the case where an `overnight` campaign was run, and logs are found in `./logs`, one can specify the exact log to use `gen-regression` with:
```bash
make gen-regression file=./logs/<logfile>
```

Overnight runs may also produce many logs for evaluation.  One can generate regressions for everything in `./logs` with:
```bash
make gen-regression-all
```

Once regressions are in their respective regression files, the `make regression` command can be used to compile and run regressions:
```bash
make regression v=1
```

This will simply run all regressions and show what is passing or failing.  An example of this output can be see here:
```bash
$ make regression v=1
./test/invariant/scripts/invariant.sh --mt=regression --v=1 --mc= "nc" --type="regression"
Running regression tests
Runs: default, Depth: default, v: -v, mt: regression, mc: all, leap: default, nc: true, fuzz-seed: 1229341307918735761
[⠰] Compiling...
No files changed, compilation skipped

Running 1 test for test/invariant/regressions/ZeroTokenRegressions.t.sol:ZeroTokenRegressionTests
[PASS] test_regression_invariant_ZT_P1_dcc5c365_failure() (gas: 537446)
Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 28.33ms

Running 2 tests for test/invariant/regressions/MinterGatewayRegressions.t.sol:MinterGatewayRegressionTests
[PASS] test_regression_invariant_MG_B5_ada5cb6a_failure() (gas: 786068)
[PASS] test_regression_invariant_MG_B8_0f887631_failure() (gas: 2768306)
Test result: ok. 2 passed; 0 failed; 0 skipped; finished in 34.91ms
 
Ran 2 test suites: 3 tests passed, 0 failed, 0 skipped (3 total tests)
```

The verbosity level of the above command is set to `4` by default, this is because one typically wants to evaluate a callstack of the regression to see what might be causing the invariant violation or emitting the error.  To inspect a specific failing test, one can use:
```bash
make regression mt=<test name>
```

## Campaign Lifecycle

The following list of steps is the typical fuzzing campaign lifecycle:
1. Run an invariant test campaign using `make invariant` or `make overnight`.
2. If an error occurs, use `make gen-regression` to generate a regression test for it.
3. Get an idea of what regression has failed with `make regression v=1`.
4. Inspect a specific regression with `make regression mt=<test name>` (e.g. `make regression mt=test_regression_invariant_ZT_P1_dcc5c365_failure`).
5. Resolve the regression by either fixing the invariant, fixing the handler, catching the error in the handler, or fixing the core code.
6. Run `make regression v=1` to ensure it's resolved and choose another test for evaluation if one exists.
7. Once all regressions are resolved, one can either remove them from the regression files manually in an editor, use `git restore <regression file>` to reset the entire file, or leave the regression in place.  **Caution, under active development, the handler calls in the regression tests are subject to change, and as they do, this will prevent the project from compiling old regressions callstacks.**  For this reason, we suggest removing old regressions until the end of active development.
8. Back to step 1. Rinse and repeat!

Happy Bug Farming
