#! /usr/bin/env python3


FNAME_IN = "./memory_trace.log"
FNAME_OUT = "./memory_trace_no_multi.log"

def main():
    with open(FNAME_IN, "r") as fd_in:
        with open(FNAME_OUT, "w") as fd_out:
            prev_line = ""
            for line in fd_in:
                if line != prev_line:
                    fd_out.write(line)
                prev_line = line



if __name__ == "__main__":
    main()
