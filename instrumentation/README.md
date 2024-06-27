# Instrumentation
This directory includes the instrumentations for our paper "On Understanding and Forecasting Fuzzers Performance with Static Analysis".
The instrumentation is based upon fuzzbench.

To obtain the static analysis data, you can run
1) `make-libafl_analysis_no_lto-<benchmark name>` to obtain the static analysis data
2) `make-libafl_lto-<benchmark name>` to obtain the fuzzer binary files.
