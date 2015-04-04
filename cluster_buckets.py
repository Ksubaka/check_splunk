#!/usr/bin/env python

from splunk import SplunkServer

import optparse


op = optparse.OptionParser()
op.add_option("-H", dest="hostname", type="string", help="IP or FQDN of the Splunk server")
op.add_option("-U", dest="username", type="string", help="Username used to log into Splunk")
op.add_option("-P", dest="password", type="string", help="Password used to log into Splunk")
op.add_option("-p", dest="port", type="int", default=8089, help="splunkd Port on server, default 8089")
op.add_option("-n", dest="use_ssl", action="store_false", default=True, help="Disable HTTPS (use http)")
(options, args) = op.parse_args()

splunkd = SplunkServer(options.hostname, options.username, options.password, options.port, options.use_ssl)

config = splunkd.cluster_config

invalid = list()
for bucket in splunkd.cluster_buckets:
    if bucket["standalone"] == "1":
        continue
    valid = 0
    complete = 0
    for (peer,info) in bucket["peers"].items():
        if info["search_state"] == "Searchable":
            valid += 1
        if info["status"] == "Complete":
            complete += 1
    if valid < int(config["search_factor"]):
        print "Bucket {0} is invalid (does not meet search factor of {1}".format(bucket["title"], config["search_factor"])
    if complete < int(config["replication_factor"]):
        print "Bucket {0} is incomplete (does not meet replication factor of {1}".format(bucket["title"], config["replication_factor"])
