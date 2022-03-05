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

    TIMESTAMP   = ("ts", -1) # ts is the first header in csv, but not in log file
    CMD         = ("cmd", 0)
    PERC_CPU    = ("%cpu", 1)
    PERC_MEM    = ("%mem", 2)
    BYTES_MEM   = ("bytes_mem", 3)

TIMESTAMP   = Stat.TIMESTAMP
CMD         = Stat.CMD
PERC_CPU    = Stat.PERC_CPU
PERC_MEM    = Stat.PERC_MEM
BYTES_MEM   = Stat.BYTES_MEM

WAZUH       = "wazuh"
OSQUERY     = "osquery"


def isint(string: str):
    try:
        int(string)
        return True
    except ValueError:
        return False


def reset_stats(cur_log: dict):
    for v in cur_log.values():
        v[PERC_CPU.value] = 0.0
        v[PERC_MEM.value] = 0.0
        v[BYTES_MEM.value] = 0


def round_percentages(cur_log: dict):
    for v in cur_log.values():
        v[PERC_CPU.value] = round(v[PERC_CPU.value], 1)
        v[PERC_MEM.value] = round(v[PERC_MEM.value], 1)


def main(args):
    stats_input_file = args[0]

    logs_dir = os.path.join(BASE_DIR, "logs")
    if not os.path.exists(logs_dir):
        os.mkdir(logs_dir)

    fieldnames = [header.value for header in Stat if header != CMD] # CMD will not be a csv header

    osqueryf = open(os.path.join(logs_dir, "osquery_stats.csv"), 'w')
    osquery_csv = csv.DictWriter(osqueryf, delimiter=';', fieldnames=fieldnames)
    osquery_csv.writeheader()

    wazuhf = open(os.path.join(logs_dir, "wazuh_stats.csv"), 'w')
    wazuh_csv = csv.DictWriter(wazuhf, delimiter=';', fieldnames=fieldnames)
    wazuh_csv.writeheader()

    with open(stats_input_file, 'r') as f:
        cur_log = {WAZUH: {}, OSQUERY: {}}
        reset_stats(cur_log)
        start_ts = None
        try:
            while True:
                line = next(f)

                if line == '\n': # new log entry in file
                    round_percentages(cur_log)
                    wazuh_csv.writerow(cur_log[WAZUH])
                    osquery_csv.writerow(cur_log[OSQUERY])
                    reset_stats(cur_log)

                elif isint(line): # first line in a log entry is a timestamp
                    ts = int(line)
                    if not start_ts:
                        start_ts = ts
                    for v in cur_log.values():
                        v[TIMESTAMP.value] = ts - start_ts

                else:
                    stats = line.split(' ')
                    key = ""
                    if WAZUH in stats[CMD.index]:
                        key = WAZUH
                    elif OSQUERY in stats[CMD.index]:
                        key = OSQUERY
                    else:
                        continue
                    
                    cur_log[key][PERC_CPU.value]    += float(stats[PERC_CPU.index])
                    cur_log[key][PERC_MEM.value]    += float(stats[PERC_MEM.index])
                    cur_log[key][BYTES_MEM.value]   += int(stats[BYTES_MEM.index])

        except StopIteration:
            # EOF
            pass

    osqueryf.close()
    wazuhf.close()


if __name__ == "__main__":
    main(sys.argv[1:])