import sys
import csv
import os
from enum import Enum

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# row indexes
class Stat(Enum):     
    def __init__(self, value, index):
        self._value_ = value
        self.index = index

    CMD         = ("cmd", 0)
    PERC_CPU    = ("%cpu", 1)
    PERC_MEM    = ("%mem", 2)
    BYTES_MEM   = ("bytes_mem", 3)

CMD         = Stat.CMD
PERC_CPU    = Stat.PERC_CPU
PERC_MEM    = Stat.PERC_MEM
BYTES_MEM   = Stat.BYTES_MEM

TIMESTAMP = "Timestamp"
TOTAL_CPU_USAGE = "Total %CPU Usage"

WAZUH       = "wazuh"
AUDIT       = "audit"
FALCO       = "falco"


def isint(string: str):
    try:
        int(string)
        return True
    except ValueError:
        return False


def reset_stats(cur_log: dict, fieldnames):
    for fname in fieldnames:
        cur_log[fname] = 0


def round_percentages(cur_log: dict, fieldnames):
    cur_log[TOTAL_CPU_USAGE] = round(cur_log[TOTAL_CPU_USAGE], 1)
    for fname in fieldnames:
        if not BYTES_MEM.value in fname:
            cur_log[fname] = round(cur_log[fname], 1)


def main(args):
    stats_input_file = args[0]

    processes = []
    # Find what processes we need to parse
    with open(stats_input_file, 'r') as f:
        try:
            while True:
                line = next(f)

                if line == '\n':
                    break
                elif WAZUH in line and WAZUH not in processes:
                    processes.append(WAZUH)
                elif AUDIT in line and AUDIT not in processes:
                    processes.append(AUDIT)
                elif FALCO in line and FALCO not in processes:
                    processes.append(FALCO)
        except StopIteration:
            # EOF
            pass

    fieldnames = [TIMESTAMP, TOTAL_CPU_USAGE]
    stat_fieldnames = []
    for proc in processes:
        stat_fieldnames += [f"{proc}_{header.value}" for header in Stat if header != CMD] # CMD will not be a csv header
    fieldnames += stat_fieldnames

    target_dir = os.path.join(BASE_DIR, "parsed_logs")
    if not os.path.exists(target_dir):
        os.mkdir(target_dir)
    target_file = f"{stats_input_file.split('/')[-1].split('.', 2)[0]}.csv"

    target_csv_file = open(os.path.join(target_dir, target_file), 'w')
    csv_writer = csv.DictWriter(target_csv_file, delimiter=';', fieldnames=fieldnames)
    csv_writer.writeheader()

    with open(stats_input_file, 'r') as f:
        cur_log = {}
        reset_stats(cur_log, fieldnames)
        start_ts = None
        try:
            while True:
                line = next(f)

                if line == '\n': # new log entry in file
                    round_percentages(cur_log, stat_fieldnames)
                    csv_writer.writerow(cur_log)
                    reset_stats(cur_log, stat_fieldnames)

                elif isint(line): # first line in a log entry is a timestamp
                    ts = int(line)
                    if not start_ts:
                        start_ts = ts
                    cur_log[TIMESTAMP] = ts - start_ts

                elif line.startswith("total cpu"):
                    total_cpu_usage = ''.join(line.split(':', 2)[1].split())
                    cur_log[TOTAL_CPU_USAGE] = float(total_cpu_usage)

                else:
                    stats = line.split(' ')
                    key = ""
                    if WAZUH in stats[CMD.index]:
                        key = WAZUH
                    elif AUDIT in stats[CMD.index]:
                        key = AUDIT
                    elif FALCO in stats[CMD.index]:
                        key = FALCO
                    else:
                        continue
                    
                    cur_log[f"{key}_{PERC_CPU.value}"]  += float(stats[PERC_CPU.index])
                    cur_log[f"{key}_{PERC_MEM.value}"]  += float(stats[PERC_CPU.index])
                    cur_log[f"{key}_{BYTES_MEM.value}"] += int(stats[BYTES_MEM.index])

        except StopIteration:
            # EOF
            pass

    target_csv_file.close()


if __name__ == "__main__":
    main(sys.argv[1:])
