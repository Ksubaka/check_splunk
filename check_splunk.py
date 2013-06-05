#!/usr/bin/env python

from splunk import SplunkServer
from xml.dom import minidom

import optparse
import pynagios
from pynagios.plugin import PluginMeta as PluginMetaBase
import string
del pynagios.Plugin._options


def add_description(description):
    def decorator(f):
        f.description = description
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
        pynagios.make_option("--index", default="main", help="For index checks: the index to check"),
    )

    check_license_opts = OptionGroup("License Check Options", "Options for license checks",
        pynagios.make_option("--license-pool", default="auto_generated_pool_enterprise", help="For license checks: the license pool to check"),
    )

    check_search_peer_opts = OptionGroup("check_search_peer Options", "Options for search peer check",
        pynagios.make_option("--search-peer", type="string", help="For check_search_peer: the indexer to verify"),
    )

    check_output_opts = OptionGroup("check_output Options", "Options for TCP output check",
        pynagios.make_option("--output", type="string", help="For check_output: the TCP output to verify"),
    )

    cluster_peer_opts = OptionGroup("check_cluster_peer Options", "Options for cluster peer check",
        pynagios.make_option("--cluster-peer", type="string", help="For check_cluster_peer: the name of the peer to verify"),
    )

    def __init__(self, *args, **kwargs):
        epilog_lines = list()
        epilog_lines.append("Valid check commands:")
        for attr in dir(self):
            if attr.startswith("check_") and callable(getattr(self, attr)):
                f = getattr(self, attr)
                command = attr[6:]
                if hasattr(f, "description"):
                    epilog_lines.append("  {}\t{}".format(string.ljust(command, 25), f.description))
                else:
                    epilog_lines.append("  {}".format(command))

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

        check = getattr(self, "check_{}".format(self.args[1]), None)
        if check is None:
            check = getattr(self, self.args[1], None)
        if callable(check):
            return check(splunkd)
        else:
            return pynagios.Response(pynagios.UNKNOWN, "Invalid check requested")

    @add_description("Check the usage of a given index")
    def check_index(self, splunkd):
        (used, capacity, pct) = splunkd.get_index_usage(self.options.index)

        output = "{}% of MaxTotalDBSize ({}) is used".format(pct, capacity)
        result = self.response_for_value(pct, output)
        result.set_perf_data("currentDBSizeMB", used, "B")
        result.set_perf_data("maxTotalDataSizeMB", capacity, "B")
        return result

    @add_description("Check the latency of a given index")
    def check_index_latency(self, splunkd):
        latency = splunkd.get_index_latency(self.options.index)

        output = "Average latency is {} seconds".format(latency)
        result = self.response_for_value(latency, output)
        result.set_perf_data("latency", latency, "s")
        return result

    @add_description("Check usage of a given license pool")
    def check_license(self, splunkd):
        (used, capacity, pct) = splunkd.get_license_pool_usage(self.options.license_pool)

        output = "{}% of license capacity ({}) is used".format(pct, capacity)
        result = self.response_for_value(pct, output)
        result.set_perf_data("license_used", used, "B")
        result.set_perf_data("license_capacity", capacity, "B")
        return result

    @add_description("Check connectivity to a given search peer")
    def check_search_peer(self, splunkd):
        status = splunkd.get_search_peer_status(self.options.search_peer)

        output = "Search peer is {}".format(status)
        return self.response_for_value(status, output, critical_value="Down", zabbix_ok="1", zabbix_critical="0")
        
    @add_description("Check the number of current running searches")
    def check_concurrent_searches(self, splunkd):
        searches = len(list(splunkd.running_jobs))

        output = "{} searches are currently running".format(searches)
        result = self.response_for_value(searches, output)
        result.set_perf_data("searches", searches)
        return result

    @add_description("Check a TCP output for connectivity to the forward-server")
    def check_output(self, splunkd):
        status = splunkd.get_tcp_output_status(self.options.output)

        output = "{} is currently in status '{}'".format(self.options.output, status)
        return self.response_for_value(status, output, ok_value="connect_done", zabbix_ok="1", zabbix_critical="0")

    @add_description("Check that a cluster peer is connected to the master")
    def check_cluster_peer(self, splunkd):
        status = splunkd.get_cluster_peer_status(self.options.cluster_peer)

        output = "Cluster peer '{}' is {}".format(self.options.cluster_peer, status)
        return self.response_for_value(status, output, ok_value="Up", zabbix_ok="1", zabbix_critical="0")

    @add_description("Check that all buckets are valid")
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

        output = "{} invalid buckets".format(len(invalid))
        result = self.response_for_value(len(invalid), output, ok_value=0)
        result.set_perf_data("invalid", len(invalid))
        return result

    @add_description("Check that all buckets are complete")
    def check_cluster_complete(self, splunkd):
        config = splunkd.cluster_config

        incomplete = list()
        for bucket in splunkd.cluster_buckets:
            if bucket["standalone"] == "1":
                continue
            complete = 0
            for (peer,info) in bucket["peers"].items():
                if info["status"] == "Complete":
                    complete += 1
            if complete < int(config["replication_factor"]):
                incomplete.append(bucket)

        output = "{} incomplete buckets".format(len(incomplete))
        result = self.response_for_value(len(incomplete), output, ok_value=0)
        result.set_perf_data("incomplete", len(incomplete))
        return result

if __name__ == "__main__":
    CheckSplunk().check().exit()
