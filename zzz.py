#!/usr/local/bin/python
import abc
import argparse
import csv
import os
import re
import sys
import typing

#  For comments check the README file

empty_line = re.compile('^\s+$')
#  The task description says the input is CSV (comma separated values), but the examples contain no comma, except in URLs
#  So lets assume: if a line contains no spaces, then this is a CSV-line, where URLs with commata are quoted,
#  otherwise the line is white-space separated
white_space_line = re.compile('\s')                  # IP                          user
line_wh = re.compile('(\d+(?:\.\d+)?)(?:\s{3,})(\d+) (\S+) (\S+) (\d+) (\S+) (\S+) (\S+) (\S+)/(\S+) (\S+)')

class Operation(abc.ABC):
    "This is an abstract class for operations"
 
    @classmethod
    @abc.abstractmethod
    def handle_line(cls, line:tuple) -> None:
        "eats a line of the input.  Line is 11-tuple"
        pass

    @classmethod
    @abc.abstractmethod
    def result(cls) -> tuple[str, float|int]:
        "Returns a tuple: ('name of the operation', result as number)"
        pass


class EventsPerSecond(Operation):
    _first_second = float('inf')
    _last_second = 0
    _num_events = 0

    @classmethod
    def handle_line(cls, line):
        try:
            timestamp = float(line[0])
            cls._num_events += 1
            cls._last_second = max(cls._last_second, timestamp)
            cls._first_second = min(cls._first_second, timestamp)
        except:  # line[0] cannot be converted to a number
            pass

    @classmethod
    def result(cls):
        return ("events per second", cls._num_events / (cls._last_second - cls._first_second or 1))


class TotalAmountOfBytesExchanged(Operation):
    _sum = 0

    @classmethod
    def handle_line(cls, line):
        try:
            cls._sum += int(line[1]) + int(line[4])
        except:  # line[1] or line[4] cannot be converted to integer
            pass

    @classmethod
    def result(cls):
        return ("total amount of bytes exchanged", cls._sum)

class MostFrequentIP(Operation):
    '''Finds the most frequently used client IP address'''
    _ips: typing.Dict[str, int] = {}  # key is the IP address, value is the number of occurrences

    @classmethod
    def handle_line(cls, line):
        ip = line[2]
        if ip in cls._ips:
            cls._ips[ip] += 1
        else:
            cls._ips[ip] = 1

    @classmethod
    def result(cls):
        most_frequent_ip = ''
        occurrences = 0
        for k, v in cls._ips.items():
            if v > occurrences:
                occurrences = v
                most_frequent_ip = k

        # returns an empty string, if the input contains no ip addresses
        return ("most frequent ip", most_frequent_ip)


class LeastFrequentIP(Operation):
    '''Finds the least frequently used client IP address'''
    _ips: typing.Dict[str, int] = {}  # key is the IP address, value is the number of occurrences

    @classmethod
    def handle_line(cls, line):
        # this is not very optimal, since the same code is executed in MostFrequentIP.handle_line()
        # but if the system is supposed to handle many, many different, independent of each other
        # operations, this is the way to go.
        ip = line[2]
        if ip in cls._ips:
            cls._ips[ip] += 1
        else:
            cls._ips[ip] = 1

    @classmethod
    def result(cls):
        least_frequent_ip = ''
        occurrences = float('inf')
        for k, v in cls._ips.items():
            if v < occurrences:
                occurrences = v
                least_frequent_ip = k

        # returns an empty string, if the input contains no ip addresses
        return ("least frequent ip", least_frequent_ip)

parser = argparse.ArgumentParser(description='Analyze log files')
parser.add_argument('--input', type=str, nargs='+',
                    help='Path to log file(s) or a directory with log files')
parser.add_argument('--most-frequent-ip', dest='operations', action='append_const', const=MostFrequentIP,
                    help='Extract the most frequest IP address')
parser.add_argument('--least-frequent-ip', dest='operations', action='append_const', const=LeastFrequentIP,
                    help='Extract the least frequest IP address')
parser.add_argument('--events-per-second', dest='operations', action='append_const', const=EventsPerSecond,
                    help='Print events per second')
parser.add_argument('--total-amount-of-bytes', dest='operations', action='append_const', const=TotalAmountOfBytesExchanged,
                    help='Total amount of bytes exchanged')
parser.add_argument('--output', type=argparse.FileType('w'), help='Output JSON file location')

def parse_line(line:str) -> typing.Optional[tuple]:
    '''returns an 11-tuple containing: timestamp, response header size, client ip address, http response code,
    response body in bytes (the assignment says “response size”, I assume this means “payload = response body
    without the headers", HTTP verb, type of access, destination IP address, MIME Type
    returns None, if the line is only white spaces, or invalid otherwise
    '''
    if empty_line.match(line):
        return
    if white_space_line.search(line[:-1]):
        l = line_wh.match(line)
        if not l:
            return
        return tuple(x for x in l.groups())
    # else the line contains comma separated values
    l = csv.reader([line]) # URLs with comma must be quoted, like
    # 1035368418.577,776,210.8.79.228,TCP_MISS/200,4797,GET,"http://www.usnews.com/RealMedia/ads/adstream_mjx.ads/www.usnews.com/nl-search/we/Archives/1272003260@Top1,Bottom1,Left1,Left2,Middle1,Right1,Right2,Right3,Right4?",-,DIRECT/64.14.118.196,application/x-javascript
    a = [x for x in l][0]
    if len(a) != 10:
        return
    # split the Type of access/destination IP address into two
    try:
        type_access, destination_ip = a[8].split('/')
        result = a[:8]
        result.extend([type_access, destination_ip, a[9]])
        return tuple(result)
    except: # The type of access/destination IP address field contains no "/"
        return

def handle_log_file(filename, operations):
    try:
        with open(filename, "r") as f:
            for line in f.readlines():
                result = parse_line(line)
                if result:
                    for op in operations:
                        op.handle_line(result)
    except: # file cannot be opened
        pass  # do not report error, skip the file

def produce_output(operations, output_file, format='json'):
    res = dict(op.result() for op in operations)
    if format == 'json':
        import json
        res = json.dumps(res, indent=4) + '\n'
    else:
        print('Unsupported output format: ' + format, file=sys.stderr)
        exit(6)

    try:
        output_file.write(res)
    except:
        print('Error writing to file ' + output_file.name, file=sys.stderr)
        exit(5)

if __name__ == "__main__":
    args = parser.parse_args()
    if not args.operations:
        print('No operation selected', file=sys.stderr)
        exit(2)

    if args.input is None:
        print('No input specified', file=sys.stderr)
        exit(1)

    if not args.output:
        print('No output file specified', file=sys.stderr)
        exit(4)

    for file in args.input:
        if not os.path.exists(file):
            print('File {} does not exist'.format(file), file=sys.stderr)
            continue
        if os.path.isdir(file):
            for filename in os.listdir(file):
                final_name = os.path.join(file, filename)
                if os.path.isfile(final_name):
                    handle_log_file(final_name, args.operations)
        else:  # file is regular
            handle_log_file(file, args.operations)
    produce_output(args.operations, args.output)
