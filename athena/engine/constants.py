#! /usr/bin/env python3


# number of bits to ignore when comparing addresses
IGNORE_LOWER_BITS = 0

LOG_STATISTICS = False

CF_STEPCOUNTER = "cf_step_counter"
DF_STEPCOUNTER = "df_step_counter"

TRACE_FILE_HEADER = "virt_addr;rip\n"

STORED_PROGRESS_STATE_FNAME = ".athena_progress.bin"
STORED_PROGRESS_META_FNAME = ".athena_progress_meta.bin"

STORED_CONSTRAINTS_FNAME = ".athena_stored_constraints.pkl"

STEPPING_STATISTICS_LOG_FNAME = "athena_stepping_statistics.csv"
DATA_CONSTRAINTS_STATISTICS_LOG_FNAME = "athena_data_constraints_statistics.csv"

MAX_CONCRETIZATION_SOLUTIONS = 1024
