#!/usr/bin/env python

from pynagios.plugin import PluginMeta as PluginMetaBase
from requests import ConnectionError
from splunk import ApiError,SplunkServer
from xml.dom import minidom

import optparse
import pynagios
import string
import time
del pynagios.Plugin._options

from requests.packages.urllib3 import disable_warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
disable_warnings(InsecureRequestWarning)


def add_description(description):
    def decorator(f):
        f.description = description
        return f
    return decorator


def add_usage(usage):
    BASE_OPTIONS = "-H 127.0.0.1 -U admin -P changeme"
    def decorator(f):
        command = f.__name__.replace("check_", "")
        if usage != "":
            f.usage = "{base} {usage} {command}".format(base=BASE_OPTIONS, usage=usage, command=command)
        else:
            f.usage = "{base} {command}".format(base=BASE_OPTIONS, command=command)
        return f
    return decorator


class OptionGroup(object):
    def __init__(self, header, helpstr, *args):
        self.header = header
        self.helpstr = helpstr
        self.options = args

    def get_option_group(self, parser):
        group = optparse.OptionGroup(parser, self.header, self.helpstr)
        group.add_options(self.options)
        return group


class OptionParser(optparse.OptionParser):
    def format_epilog(self, formatter):
        return "\n" + self.epilog + "\n"


class ZabbixResponse(pynagios.Response):
    def __str__(self):
        return str(self.message)


class PluginMeta(PluginMetaBase):
    """
    We use a metaclass to create the plugins in order to gather and
    set up things such as command line arguments.

    This is overridden to provide usage and option group support
    """

    def __new__(cls, name, bases, attrs):
        attrs = attrs if attrs else {}

        # Set the options on the plugin by finding all the Options and
        # setting them. This also removes the original Option attributes.
        global_options = []
        groups = []

        option_parser = OptionParser()

        for key,val in attrs.items():
            if key == "_usage":
                option_parser.set_usage(val)
                del attrs[key]
            elif isinstance(val, optparse.Option):
                # We set the destination of the Option to always be the
                # attribute key...
                val.dest = key

                # Append it to the list of options and delete it from
                # the original attributes list
                global_options.append(val)
                del attrs[key]
            elif isinstance(val, OptionGroup):
                groups.append(val.get_option_group(option_parser))

        # Need to iterate through the bases in order to extract the
        # list of parent options, so we can inherit those.
        for base in bases:
            if hasattr(base, "_options"):
                options.extend(getattr(base, "_options"))

        option_parser.add_options(global_options)
        for group in groups:
            option_parser.add_option_group(group)

        # Store the option list and create the option parser
        attrs["_option_parser"] = option_parser
        attrs["_options"] = global_options

        # Create the class, skipping the immediate parent
        return super(PluginMetaBase, cls).__new__(cls, name, bases, attrs)


class CheckSplunk(pynagios.Plugin):
    __metaclass__ = PluginMeta

    _usage = "usage: %prog [options] command"
    hostname = pynagios.make_option("-H", type="string", help="IP or FQDN of the Splunk server")
    username = pynagios.make_option("-U", type="string", help="Username used to log into Splunk")
    password = pynagios.make_option("-P", type="string", help="Password used to log into Splunk")
    port = pynagios.make_option("-p", type="int", default=8089, help="splunkd Port on server, default 8089")
    use_ssl = pynagios.make_option("-n", action="store_false", default=True, help="Disable HTTPS (use http)")
    zabbix = pynagios.make_option("-Z", action="store_true", default=False, help="Output in Zabbix format")
    warning = pynagios.make_option("-w", type="int", help="Warning level")
    critical = pynagios.make_option("-c", type="int", help="Critical level")

    check_index_opts = OptionGroup("Index Check Options", "Options for the index checks",
        pynagios.make_option("--index", default="main", help="Name of a Splunk index, default is 'main'"),
    )

    check_license_opts = OptionGroup("License Check Options", "Options for license checks",
        pynagios.make_option("--license-pool", default="auto_generated_pool_enterprise", help="Name of a Splunk license pool, default is 'auto_generated_pool_enterprise'"),
        pynagios.make_option("--capacity", default=0, help="Capactiy to consider 100%, defaults to pool capacity"),
    )

    check_search_peer_opts = OptionGroup("check_search_peer Options", "Options for search peer check",
        pynagios.make_option("--search-peer", type="string", help="Name of an indexer used by this search head"),
    )

    check_output_opts = OptionGroup("check_output Options", "Options for TCP output check",
        pynagios.make_option("--appname", type="string", help="App containing the output"),
        pynagios.make_option("--output", type="string", help="Host/port pair of a forward-server"),
    )

    check_cluster_peer_opts = OptionGroup("check_cluster_peer Options", "Options for cluster peer check",
        pynagios.make_option("--cluster-peer", type="string", help="Name of a cluster slave (indexer)"),
    )

    check_deployment_client_opts = OptionGroup("check_deployment_client Options", "Options for deployment client check",
        pynagios.make_option("--deployment-client", type="string", help="IP, Hostname or ID of a deployment client")
    )

    def __init__(self, *args, **kwargs):
        epilog_lines = list()
        epilog_lines.append("Valid check commands:")
        for attr in dir(self):
            if attr.startswith("check_") and callable(getattr(self, attr)):
                f = getattr(self, attr)
                command = attr[6:]
                if hasattr(f, "description"):
                    epilog_lines.append("  {0}{1}".format(string.ljust(command, 30), f.description))
                else:
                    epilog_lines.append("  {0}".format(command))
                if hasattr(f, "usage"):
                    epilog_lines.append("    Usage:")
                    epilog_lines.append(self._option_parser.expand_prog_name("      %prog {0}".format(f.usage)))

        self._option_parser.epilog = "\n".join(epilog_lines)

        super(CheckSplunk, self).__init__(*args, **kwargs)

    def response_for_value(self, value, message=None, ok_value=None, critical_value=None, zabbix_ok=None, zabbix_critical=None):
        if critical_value is None and ok_value is None:
            if value >= self.options.critical:
                ret = pynagios.CRITICAL
            elif value >= self.options.warning:
                ret = pynagios.WARNING
            else:
                ret = pynagios.OK
        else:
            if ok_value is not None and critical_value is not None:
                if value == critical_value:
                    ret = pynagios.CRITICAL
                elif value == ok_value:
                    ret = pynagios.OK
                else:
                    ret = pynagios.UNKNOWN
            elif ok_value is None:
                if value == critical_value:
                    ret = pynagios.CRITICAL
                else:
                    ret = pynagios.OK
            elif critical_value is None:
                if value == ok_value:
                    ret = pynagios.OK
                else:
                    ret = pynagios.CRITICAL
            else:
                ret = pynagios.UNKNOWN

        if self.options.zabbix or message is None:
            if ret == pynagios.OK and zabbix_ok:
                return ZabbixResponse(ret, zabbix_ok)
            elif ret == pynagios.CRITICAL and zabbix_critical:
                return ZabbixResponse(ret, zabbix_critical)
            return ZabbixResponse(ret, value)
        else:
            return pynagios.Response(ret, message)

    def check(self):
        #try:
        splunkd = SplunkServer(self.options.hostname, self.options.username, self.options.password, self.options.port, self.options.use_ssl)
        #except:
        #    return pynagios.Response(pynagios.UNKNOWN, "Failed to login to splunkd")

        check = getattr(self, "check_{0}".format(self.args[1]), None)
        if check is None:
            check = getattr(self, self.args[1], None)
        if callable(check):
            try:
                return check(splunkd)
            except ConnectionError:
                return pynagios.Response(pynagios.CRITICAL, "Unable to connect to splunkd")
            except ApiError as e:
                return pynagios.Response(pynagios.CRITICAL, str(e))
        else:
            return pynagios.Response(pynagios.UNKNOWN, "Invalid check requested")

    @add_description("Check the usage of a given index (indexer)")
    @add_usage("--index=main -w 80 -c 90")
    def check_index(self, splunkd):
        try:
            (used, capacity, pct) = splunkd.get_index_usage(self.options.index)
        except AttributeError:
            return pynagios.Response(pynagios.CRITICAL, "{0} index not found".format(self.options.index))

        output = "{0}% of MaxTotalDBSize ({1}) is used".format(pct, capacity)
        result = self.response_for_value(pct, output)
        result.set_perf_data("currentDBSizeMB", used * 1048576, "B")
        result.set_perf_data("maxTotalDataSizeMB", capacity * 1048576, "B")
        return result

    @add_description("Check the latency of a given index (indexer)")
    @add_usage("--index=main -w 5 -c 10")
    def check_index_latency(self, splunkd):
        latency = splunkd.get_index_latency(self.options.index)

        output = "Average latency is {0} seconds".format(latency)
        result = self.response_for_value(latency, output)
        result.set_perf_data("latency", latency, "s")
        return result

    @add_description("Check usage of a given license pool (licensemaster)")
    @add_usage("--license-pool=auto_generated_pool_enterprise")
    def check_license(self, splunkd):
        (used, capacity, pct) = splunkd.get_license_pool_usage(self.options.license_pool)

        if self.options.capacity != 0:
            capacity = int(self.options.capacity)
            pct = int(used * 100 / capacity)

        output = "{0}% of license capacity ({1}) is used".format(pct, capacity)
        result = self.response_for_value(pct, output)
        result.set_perf_data("license_used", used, "B")
        result.set_perf_data("license_capacity", capacity, "B")
        return result

    @add_description("Check connectivity to the license master (all)")
    @add_usage("-w 60 -c 120")
    def check_license_master(self, splunkd):
        info = splunkd.license_slave_info
        last_success = info["last_master_contact_success_time"]
        last_attempt = info["last_master_contact_attempt_time"]

        success_diff = int(time.time()) - int(last_success)

        output = "Last connected to master {0} seconds ago".format(success_diff)
        return self.response_for_value(success_diff, output, zabbix_ok="1", zabbix_critical="0")

    @add_description("Check connectivity to a given search peer (searchhead, cluster-master)")
    @add_usage("--search-peer=acme-corp-indexer-01")
    def check_search_peer(self, splunkd):
        status = splunkd.get_search_peer_status(self.options.search_peer)

        output = "Search peer is {0}".format(status)
        return self.response_for_value(status, output, critical_value="Down", zabbix_ok="1", zabbix_critical="0")
        
    @add_description("Check the number of current running searches (searchhead)")
    @add_usage("-w 25 -c 50")
    def check_concurrent_searches(self, splunkd):
        searches = len(list(splunkd.running_jobs))

        output = "{0} searches are currently running".format(searches)
        result = self.response_for_value(searches, output)
        result.set_perf_data("searches", searches)
        return result

    @add_description("Check a TCP output for connectivity to the forward-server (forwarder)")
    @add_usage("--output=192.168.1.1:9997")
    def check_output(self, splunkd):
        status = splunkd.get_tcp_output_status(self.options.appname, self.options.output)

        output = "{0} is currently in status '{1}'".format(self.options.output, status)
        return self.response_for_value(status, output, ok_value="connect_done", zabbix_ok="1", zabbix_critical="0")

    @add_description("Check that a cluster peer is connected to the master (cluster-master)")
    @add_usage("--cluster-peer=acme-corp-indexer-01")
    def check_cluster_peer(self, splunkd):
        status = splunkd.get_cluster_peer_status(self.options.cluster_peer)

        output = "Cluster peer '{0}' is {1}".format(self.options.cluster_peer, status)
        return self.response_for_value(status, output, ok_value="Up", zabbix_ok="1", zabbix_critical="0")

    @add_description("Check that all buckets are valid (cluster-master)")
    @add_usage("")
    def check_cluster_valid(self, splunkd):
        config = splunkd.cluster_config

        invalid = list()
        for bucket in splunkd.cluster_buckets:
            if bucket["standalone"] == "1":
                continue
            valid = 0
            for (peer,info) in bucket["peers"].items():
                if info["search_state"] == "Searchable":
                    valid += 1
            if valid < int(config["search_factor"]):
                invalid.append(bucket)

        output = "{0} invalid buckets".format(len(invalid))
        result = self.response_for_value(len(invalid), output, ok_value=0)
        result.set_perf_data("invalid", len(invalid))
        return result

    @add_description("Check that all buckets are complete (cluster-master)")
    @add_usage("")
    def check_cluster_complete(self, splunkd):
        config = splunkd.cluster_config

        incomplete = list()
        for bucket in splunkd.cluster_buckets:
            if bucket["standalone"] == "1":
                continue
            complete = 0
            for (peer,info) in bucket["peers"].items():
                if info["status"] in ("Complete", "StreamingSource", "StreamingTarget"):
                    complete += 1
            if complete < int(config["replication_factor"]):
                incomplete.append(bucket)

        output = "{0} incomplete buckets".format(len(incomplete))
        result = self.response_for_value(len(incomplete), output, ok_value=0)
        result.set_perf_data("incomplete", len(incomplete))
        return result

    @add_description("Verify slave is connected to master (indexer)")
    @add_usage("")
    def check_cluster_connection(self, splunkd):
        connected = bool(splunkd.cluster_slave_info["is_registered"] == "1")

        master = splunkd.cluster_config["master_uri"]

        output = "Connected to {0}".format(master) if connected else "Disconnected"
        return self.response_for_value(connected, output, ok_value=True, zabbix_ok="1", zabbix_critical="0")

    @add_description("Verify clustering status of slave (indexer)")
    @add_usage("")
    def check_cluster_status(self, splunkd):
        status = splunkd.cluster_slave_info["status"]

        output = "Slave is {0}".format(status)
        return self.response_for_value(status, output, ok_value="Up", zabbix_ok="1", zabbix_critical="0")

    @add_description("Verify a deployment client has checked in (deployment-server)")
    @add_usage("--deployment-client=192.168.1.1")
    def check_deployment_client(self, splunkd):
        try:
            phoneHomeTime = splunkd.get_deployment_client_info(self.options.deployment_client)["phoneHomeTime"]
        except StopIteration:
            return pynagios.Response(pynagios.CRITICAL, "Unable to get phone home time for {0}".format(self.options.deployment_client))

        import datetime
        dt = datetime.datetime.strptime(phoneHomeTime, "%a %b %d %H:%M:%S %Y")
        diff = (datetime.datetime.now() - dt).seconds

        output = "Client checked in {0} seconds ago".format(diff)
        return self.response_for_value(diff, output, zabbix_ok="1", zabbix_critical="0")

#    @add_description("Return the given field from the first search result of the given search")
#    @add_usage("--search='host=X sourcetype=Y' --earliest-time='-1h@h' --latest-time='@h' --field=Z")
#    def check_search_result(self, splunkd):
#        result = splunkd.get_search_first_result(self.options.search, self.options.field, self.options.earliest, self.options.latest)
#
#        output = "Result: {0}={1}".format(field, result)
#        return self.response_for_value(result, output)

    @add_description("Check bundle replication status")
    def check_distributed_search_peers(self, splunkd):
        failedPeers = list()
        for peer in splunkd.distributed_search_peers:
            if peer["replicationStatus"] != "Successful":
                failedPeers.append(peer["guid"])

        if len(failedPeers) == 0:
            return pynagios.Response(pynagios.OK, "All peers replicating successfully")
        else:
            return pynagios.Response(pynagios.CRITICAL, "Peers failed replication: %s" % ",".join(failedPeers))

    @add_description("Check for messages displayed in the Splunk UI")
    @add_usage("")
    def check_messages(self, splunkd):
        count = len(list(splunkd.messages))

        output = "{0} messages in Splunk UI".format(count)
        return self.response_for_value(count, output, ok_value=0, zabbix_ok="1", zabbix_critical="0")

if __name__ == "__main__":
    try:
        CheckSplunk().check().exit()
    except Exception as e:
        import sys
        import traceback
        print "CRITICAL :: Exception follows"
        print traceback.format_exc().strip()
        sys.exit(2)
