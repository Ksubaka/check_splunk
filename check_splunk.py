#!/usr/bin/env python

import argparse
import pynagios
import time
import warnings

import requests


class SearchError(Exception):
    def __init__(self, error, *args, **kwargs):
        super(SearchError, self).__init__(*args, **kwargs)
        self.error = error


check_splunk_configuration = {
    "check_index_usage": {
        "search": """
| rest /servicesNS/nobody/system/data/indexes/{index} splunk_server=local
| eval pct=(currentDBSizeMB * 100 / maxTotalDataSizeMB)
| eval pct=round(pct, 1)
| eval message=pct."% of maxTotalDataSizeMB (".maxTotalDataSizeMB.") is used"
| eval status=case(pct >= {critical}, "CRITICAL", pct >= {warning}, "WARNING", pct < {warning}, "OK")
| eval currentDBSizeMB=currentDBSizeMB." mb"
| eval maxTotalDataSizeMB=maxTotalDataSizeMB." mb"
| fields + status,message,currentDBSizeMB,maxTotalDataSizeMB
            """.strip(),
        "args": {
            "index": (str, "Name of a Splunk index, default is 'main'", "main"),
            "warning": (int, "Warning threshold, as percentage, default is 80%", 80),
            "critical": (int, "Critical threshold, as percentage, default is 90%", 80),
        },
        "failure": ("CRITICAL", "Index {index} not found"),
        "description": "Check the usage of a given index (indexer)",
    },

    "check_license_usage": {
        "search": """
| rest /servicesNS/nobody/system/licenser/pools/{license_pool} splunk_server=local
| eval pct=(used_bytes * 100 / effective_quota)
| eval pct=round(pct, 1)
| eval message=pct."% of license capacity (".effective_quota.") is used"
| eval status=case(pct >= {critical}, "CRITICAL", pct >= {warning}, "WARNING", pct < {warning}, "OK")
| eval used_bytes=round(used_bytes/1048675, 0)." mb"
| eval effective_quota=round(effective_quota/1048576, 0)." mb"
| fields + status,message,used_bytes,effective_quota
            """.strip(),
        "args": {
            "license_pool": (str, "Name of a Splunk license pool, default is "
                             "'auto_generated_pool_enterprise",
                             "auto_generated_pool_enterprise"),
            "warning": (int, "Warning threshold, as percentage, default is 80%", 80),
            "critical": (int, "Critical threshold, as percentage, default is 90%", 80),
        },
        "description": "Check usage of a given license pool (licensemaster)",
        "failure": ("UNKNOWN", "License pool '{license_pool}' not found"),
    },

    "check_license_master": {
        "search": """
| rest /services/licenser/localslave splunk_server=local
| eval diff=now()-last_master_contact_success_time
| eval message="Last connected to master ".diff." seconds ago"
| eval status=case(diff >= {critical}, "CRITICAL", diff >= {warning}, "WARNING", diff < {warning}, "OK")
| fields + status,message
            """.strip(),
        "args": {
            "warning": (int, "Warning threshold, in seconds, default is 3600", 3600),
            "critical": (int, "Critical threshold, as percentage, default is 7200", 3600),
        },
        "description": "Check connectivity to the license master (all)",
    },

    "check_search_peer": {
        "search": """
| rest /services/search/distributed/peers splunk_server=local
| search host={search_peer}* OR peerName={search_peer}* OR title={search_peer}*
| eval message="Search peer ".host." is ".status
| eval status=case(status == "Up", "OK", status != "Up", "CRITICAL")
| fields + status,message
            """.strip(),
        "args": {
            "search_peer": (str, "Name of an indexer used by this search head", None)
        },
        "failure": ("CRITICAL", "Peer {search_peer} not found"),
        "description": "Check connectivity to a given search peer (searchhead, cluster-master)"
    },

    "check_concurrent_searches": {
        "search": """
| rest /services/search/jobs splunk_server=local
| search dispatchState="RUNNING"
| stats count
| eval message=count." searches are currently running"
| appendcols [| rest /services/admin/server-status-limits-concurrency splunk_server=local | fields + max_hist_searches]
| eval warning=round({warning} * max_hist_searches, 0) + 1
| eval critical=round({critical} * max_hist_searches, 0) + 1
| eval status=case(count >=critical, "CRITICAL", count >= warning, "WARNING", count < warning, "OK")
| rename count as running_searches
| fields + status,message,running_searches,max_hist_searches
            """.strip(),
        "description": "Check the number of current running searches (searchhead)",
        "args": {
            "warning": (int, "Warning threshold, as percentage, default is 80%", 80),
            "critical": (int, "Critical threshold, as percentage, default is 90%", 80),
        },
    },

    "check_output": {
        "search": """
| rest /servicesNS/nobody/system/data/outputs/tcp/server/ splunk_server=local
| search destHost={output}* OR destIp={output}*
| eval message=destHost." is currently in status ".status
| eval status=case(status=="connect_done", "OK", status!="connect_done", "CRITICAL")
| fields + status,message
            """.strip(),
        "args": {
            "output": (str, "Host/port pair of a forward-server", None),
        },
        "description": "Check a TCP output for connectivity to the forward-server (forwarder)",
        "failure": ("UNKNOWN", "Forward-server {output} not found"),
    },

    "check_cluster_peer": {
        "search": """
| rest /services/cluster/master/peers splunk_server=local
| search host_port_pair={cluster_peer}* OR label={cluster_peer}*
| eval message="Cluster peer ".label." is ".status
| eval status=if(status=="Up", "OK", "CRITICAL")
| fields + status,message
            """.strip(),
        "args": {
            "cluster_peer": (str, "Name of a cluster slave (indexer)", None)
        },
        "description": "Check that a cluster peer is connected to the master (cluster-master)",
    },

    "check_cluster_valid": {
        "search": r"""
| rest /services/cluster/config splunk_server=local | fields + search_factor
| map search="| rest /services/cluster/master/buckets splunk_server=local
| search NOT standalone=1 NOT frozen=1
| eval searchable="None"
| foreach *search_state [eval searchable=mvappend(searchable, '<<FIELD>>')]
| eval searchable=mvfilter(searchable==\"Searchable\")
| eval searchable=mvcount(searchable)
| eval searchable=if(searchable<$search_factor$, \"no\", \"yes\")
| stats count(searchable==\"no\") as invalid, count as total_buckets"
| eval message=invalid." invalid buckets"
| eval status=if(invalid==0, "OK", "CRITICAL")
| eval total_buckets=total_buckets." c"
            """.strip(),
        "description": "Check that all buckets are valid (cluster-master)",
    },

    "check_cluster_complete": {
        "search": r"""
| rest /services/cluster/config splunk_server=local | fields + replication_factor
| map search="| rest /services/cluster/master/buckets splunk_server=local
| search NOT standalone=1 NOT frozen=1
| eval complete="None"
| foreach *status [eval complete=mvappend(complete, '<<FIELD>>')]
| eval complete=mvfilter(complete==\"Complete\" OR complete==\"StreamingSource\" OR complete==\"StreamingTarget\")
| eval complete=mvcount(complete)
| eval complete=if(complete<$replication_factor$, \"no\", \"yes\")
| stats count(complete=="no") as incomplete, count as total_buckets"
| eval message=incomplete." incomplete buckets"
| eval status=if(incomplete==0, "OK", "CRITICAL")
| eval total_buckets=total_buckets." c"
| fields + status,message,incomplete,total_buckets
            """.strip(),
        "description": "Check that all buckets are complete (cluster-master)",
    },

    "check_cluster_connection": {
        "search": """
| rest /services/cluster/slave/info splunk_server=local
| stats count by is_registered
| appendcols [| rest /services/cluster/config | fields + master_uri]
| eval message=if(is_registered=="1", "Connected to ".master_uri, "Not connected to ".master_uri)
| eval status=if(is_registered=="1", "OK", "CRITICAL")
| fields + status,message
            """.strip(),
        "description": "Verify slave is connected to master (indexer)",
    },

    "check_cluster_status": {
        "search": """
| rest /services/cluster/slave/info splunk_server=local
| eval message="Slave is ".status
| eval status=if(status=="Up", "OK", "CRITICAL")
| fields + status,message
            """.strip(),
        "description": "Verify clustering status of slave (indexer)",
    },

    "check_deployment_client": {
        "search": """
| rest "/services/deployment/server/clients?count=0" splunk_server=local
| search id={deployment_client} OR ip={deployment_client} OR hostname={deployment_client} OR dns={deployment_client}
| eval phoneHomeTime=coalesce(phoneHomeTime, lastPhoneHomeTime)
| eval diff=now()-phoneHomeTime
| eval message="Client checked in ".diff." seconds ago"
| eval status=case(diff>={critical}, "CRITICAL", diff>={warning}, "WARNING", diff<{warning}, "OK")
| fields + status,message
            """.strip(),
        "args": {
            "deployment_client": (str, "IP, Hostname or ID of a deployment client", None),
            "warning": (int, "Warning threshold, in seconds, default is 3600", 3600),
            "critical": (int, "Critical threshold, as percentage, default is 7200", 3600),
        },
        "failure": ("CRITICAL", "Unable to get phone home time for {deployment_client}"),
        "description": "Verify a deployment client has checked in (deployment-server)",
    },

    "check_distributed_search_peers": {
        "search": """
| rest /servicesNS/nobody/system/search/distributed/peers splunk_server=local
| stats count(eval(replicationStatus="Successful")) as successful_peers, count(eval(replicationStatus!="Successful")) as failed_peers
| eval status=if(failed_peers==0, "OK", "CRITICAL")
| eval message=if(failed_peers==0, "All peers replicating successfully", failed_peers." peers failed replication")
| fields + status,message,successful_peers,failed_peers
            """.strip(),
        "failure": ("CRITICAL", "No distributed search peers found"),
        "description": "Check bundle replication status (search-head)",
    },

    "check_messages": {
        "search": """
| rest /services/messages
| stats count as messages
| eval status=if(messages>0, "CRITICAL", "OK")
| eval message=messages." messages in Splunk UI"
| fields + status,message,messages
            """.strip(),
        "description": "Check for messages displayed in the Splunk UI",
    },

    "check_opsec_lea": {
        "search": """
| rest /servicesNS/nobody/-/opsec/entity_health/{opsec_entity} splunk_server=local
| eval last_connection_timestamp=strptime(last_connection_timestamp, "%Y-%m-%dT%H:%M:%SZ")
| eval diff=round(last_connection_timestamp-now(), 0)
| eval status=case(diff>={critical}, "CRITICAL", diff>={warning}, "WARNING", diff<{warning}, "OK")
| eval message="Last connected ".diff." seconds ago"
| fields + status,message
            """.strip(),
        "args": {
            "opsec_entity": (str, "Name of OPSEC entity to check", None),
            "warning": (int, "Warning threshold, in seconds, default is 3600", 3600),
            "critical": (int, "Critical threshold, as percentage, default is 7200", 3600),
        },
        "description": "Check status of an OPSEC LEA entity",
    },
}


class CheckSplunk:
    def __init__(self):
        self.argparser = argparse.ArgumentParser()

        # Global arguments
        self.argparser.add_argument("-H", dest="hostname", type=str, required=True,
                                    help="IP or FQDN of the Splunk server")
        self.argparser.add_argument("-U", dest="username", type=str, required=True,
                                    help="Username used to log into Splunk")
        self.argparser.add_argument("-P", dest="password", type=str, required=True,
                                    help="Password used to log into Splunk")
        self.argparser.add_argument("-p", dest="port", type=int, default=8089,
                                    help="splunkd Port on server, default 8089")
        self.argparser.add_argument("-n", dest="scheme", action="store_const", default="https",
                                    const="http", help="Disable HTTPS (use http)")
        self.argparser.add_argument("-t", dest="timeout", type=int, default=60,
                                    help="Amount of time before giving up")

        subparsers = self.argparser.add_subparsers()
        for (check_name, check_config) in check_splunk_configuration.items():
            check_arg_parser = subparsers.add_parser(check_name, help=check_config["description"])
            check_arg_parser.set_defaults(check_name=check_name)
            if "args" not in check_config:
                continue
            for (arg, arg_config) in check_config["args"].items():
                long_arg = "--{0}".format(arg.replace("_", "-"))
                if arg_config[2] is None:
                    kwargs = {"required": True}
                else:
                    kwargs = {"default": arg_config[2]}
                check_arg_parser.add_argument(long_arg, dest=arg, type=arg_config[0],
                                              help=arg_config[1], **kwargs)

        self.sess = requests.Session()
        self.sess.auth = (self.options.username, self.options.password)

    @property
    def options(self):
        return self.argparser.parse_args()

    @property
    def url(self):
        return "{0.scheme}://{0.hostname}:{0.port}/services/search/jobs".format(self.options)

    def get_job_url(self, sid):
        return "{0}/{1}/results".format(self.url, sid)

    def get_job_results(self, sid):
        url = self.get_job_url(sid)

        timeout = time.time() + self.options.timeout
        while time.time() < timeout:
            r = self.sess.get(url, params={"output_mode": "json"}, verify=False)
            if r.status_code != 204:
                break
            time.sleep(1)

        if r.status_code == 204:
            raise TimeoutError()
        elif r.status_code != 200:
            raise SearchError(r.json()["messages"][0]["text"])

        return r.json()["results"]

    def run_search(self, search, failure=None):
        data = {
            "search": search.format(**vars(self.options)),
            "output_mode": "json",
        }

        r = self.sess.post(self.url, data=data, verify=False)
        if r.status_code != 201:
            error = r.json()["messages"][0]["text"]
            if error == "Unauthorized":
                status = "CRITICAL"
                message = "{0.username} requires 'search' capability".format(self.options)
            else:
                status = "UNKNOWN"
                message = "Unable to execute search: {0}".format(error)
            return (status, message, {})

        sid = r.json()["sid"]

        try:
            results = self.get_job_results(sid)
        except SearchError as ex:
            return ("CRITICAL", "Error executing search: {0.error}".format(ex), {})
        except TimeoutError as ex:
            return ("CRITICAL", "Timeout executing search", {})

        if len(results) > 0:
            result = results[0]

            status = result.pop("status", "UNKNOWN")
            message = result.pop("message", "No information")
        else:
            if failure is None:
                (status, message) = ("UNKNOWN", "No results returned")
            else:
                (status, message) = failure
            result = {}

        return (status, message, result)

    def check(self):
        config = check_splunk_configuration[self.options.check_name]
        search = config["search"]
        failure = config.get("failure", None)

        (status, message, perf_data) = self.run_search(search, failure)

        status = getattr(pynagios, status, pynagios.UNKNOWN)
        response = pynagios.Response(status, message.format(**vars(self.options)))
        for (key, val) in perf_data.items():
            try:
                (val, uom) = val.split(" ", 1)
            except:
                uom = None
            response.set_perf_data(key, val, uom)

        return response


if __name__ == "__main__":
    warnings.simplefilter("ignore")
    CheckSplunk().check().exit()
