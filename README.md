# fuzzing-static-analysis

This repo is consisted of following folders;

- `instrumentation/` contains the LLVM instrumentation.
- `feature/` contains the all the scripts used to collect the data gathered and process them.
	- `feature/lto/` contains the script to extract function signatures from the lto binaries.
	- `feature/feature/` contains the script to extract the features from the raw data and summarize it as txt	
	- `feature/corpus/` contains the script to extract the features of the initial corpus coverage. This data was generated using `make build-coverage-<benchmark name>` in the fuzzbench directory, and manually running llvm-cov
- `correlation` contains the script used to conduct the correlation analysis.
	- `correlation/experiments/coverage_exp` contains the raw experiment data from fuzzbench
	- `correlation/experiments/data` contains the output from the feature extraction scripts used in `feature/`. This data is for fuzzbench programs.
	- `correlation/experiments/data_sbft` contains the output from the feature extraction scripts used in `feature/`. This data is for sbft'23 programs in fuzzbench.
	- `correlation/scripts/` contains the script to conduct the correlation analysis. Cohen.ipynb is used for the pearson's correlation, and Spearman.ipynb is used for the rank correlation.
	- `correlation/scripts/fncov_getter.py` is the script to get the function coverage from the experiment data on fuzzbench
	- `correlation/scripts/fncov.py` is the script to get the actual correlation with the function coverage instead of branch coverage.
- `prediction` contains the script used to conduct the perdiction using random forest
	- `prediction/prediction.py` is the main script to perform the actual prediction
	- `prediction/driver.py` is the script to run the prediction for every fuzzer and compile the fuzzer into a tex table

For the fuzzers we used in the experiment, see https://github.com/AFLplusplus/libafl_fuzzbench. 
This repo contains all the repo we used to conduct the correlation analysis 