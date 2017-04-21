from ripe.atlas.cousteau import MeasurementRequest
from collections import defaultdict
from datetime import datetime
from ripe.atlas.sagan import Result
import urllib.request
from ripe.atlas.cousteau import AtlasResultsRequest
from ipaddress import ip_address
import pytricia
import csv

ixp_prefixes = pytricia.PyTricia()

with open("ix_prefixes.csv") as inputfile:
    reader = csv.DictReader(inputfile)
    for row in reader:
        ixp_prefixes[row['prefix']] = row['ix_name']        

kwargs = {
    "msm_id": 5001,
    "start": datetime(2017, 4, 18),
    "stop": datetime(2017, 4, 19),
#    "probe_ids": list(range(0,100))
}

is_success, results = AtlasResultsRequest(**kwargs).create()

if is_success:
    print("Succes!")
else:
    exit

fail_count = 0
with open("result.dat", "w") as outputfile:
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
