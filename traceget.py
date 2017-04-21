from ripe.atlas.cousteau import MeasurementRequest
from collections import defaultdict
from datetime import datetime
from ripe.atlas.sagan import Result
import urllib.request
from ripe.atlas.cousteau import AtlasResultsRequest
from ipaddress import ip_address
import pytricia
import csv
import argparse
import pytz

def valid_date(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d-%H-%M")
    except ValueError:
        msg = "Not a valid date: '{}'.".format(s)
        raise argparse.ArgumentTypeError(msg)

parser = argparse.ArgumentParser(description='Get traceroutes from measurement in -a- format')
parser.add_argument('-s', "--start", help="The start time (format: YYYY-MM-DD-HH-MM)", required=True, type=valid_date)
parser.add_argument('-e', "--end", help="The end time (format: YYYY-MM-DD-HH-MM)", required=True, type=valid_date)
parser.add_argument('-m', "--msmid", help="The measurement ID", required=True, type=int)
args = parser.parse_args()

ixp_prefixes = pytricia.PyTricia()

with open("ix_prefixes.csv") as inputfile:
    reader = csv.DictReader(inputfile)
    for row in reader:
        ixp_prefixes[row['prefix']] = row['ix_name']

kwargs = {
    "msm_id": args.msmid,
    "start": args.start,
    "stop": args.end,
}

is_success, results = AtlasResultsRequest(**kwargs).create()

if is_success:
    print("Succes!")
else:
    exit

filename = "results_{}_{}_{}.dat".format(args.start.strftime("%Y%m%d%H%M"),args.end.strftime("%Y%m%d%H%M"),args.msmid)

fail_count = 0
with open(filename, "w") as outputfile:
    for result in results:
        tr = Result.get(result)
        ip_list = []
        failed = False
        for hop in tr.hops:
            ips = list(set([ip_address(x.origin) for x in hop.packets if x is not None and x.origin is not None]))
            if len(ips) == 0:
                ip_list.append("*")
            elif len(ips) > 1:
                failed = True
                fail_count += 1
                break
            else:
                if ips[0] in ixp_prefixes:
                    ip_list.append("IX:{}".format(ixp_prefixes[ips[0]]))
                elif ips[0].is_global:
                    ip_list.append("IP:{}".format(str(ips[0])))
        if not failed and len(ip_list) > 0:
            print(tr.probe_id, file=outputfile)
            print(tr.origin, file=outputfile)
            print(tr.created.strftime("%s"), file=outputfile)
            print("\n".join(ip_list), file=outputfile)
            print(".", file=outputfile)
