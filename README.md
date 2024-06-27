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
