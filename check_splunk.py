#!/usr/bin/env python

from splunk import SplunkServer

from xml.dom import minidom

import pynagios
del pynagios.Plugin._options


class ZabbixResponse(pynagios.Response):
    def __str__(self):
        return str(self.message)


class CheckSplunk(pynagios.Plugin):
    hostname = pynagios.make_option("-H", type="string")
    username = pynagios.make_option("-U", type="string")
    password = pynagios.make_option("-P", type="string")
    port = pynagios.make_option("-p", type="int", default=8089)
    use_ssl = pynagios.make_option("-n", action="store_false", default=True)
    zabbix = pynagios.make_option("-Z", action="store_true", default=False)
    warning = pynagios.make_option("-w", type="int")
    critical = pynagios.make_option("-c", type="int")

    # check_index, check_index_latency
    index = pynagios.make_option("-I", default="main")

    # check_license
    license_pool = pynagios.make_option("-L", default="auto_generated_pool_enterprise")

    # check_search_peer (runs on search_head)
    search_peer = pynagios.make_option("-S", type="string")

    # check_output
    output = pynagios.make_option("-O", type="string")

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

    def check_index(self, splunkd):
        (used, capacity, pct) = splunkd.get_index_usage(self.options.index)

        output = "{}% of MaxTotalDBSize ({}) is used".format(pct, capacity)
        result = self.response_for_value(pct, output)
        result.set_perf_data("currentDBSizeMB", used, "B")
        result.set_perf_data("maxTotalDataSizeMB", capacity, "B")
        return result

    def check_index_latency(self, splunkd):
        latency = splunkd.get_index_latency(self.options.index)

        output = "Average latency is {} seconds".format(latency)
        result = self.response_for_value(latency, output)
        result.set_perf_data("latency", latency, "s")
        return result

    def check_license(self, splunkd):
        (used, capacity, pct) = splunkd.get_license_pool_usage(self.options.license_pool)

        output = "{}% of license capacity ({}) is used".format(pct, capacity)
        result = self.response_for_value(pct, output)
        result.set_perf_data("license_used", used, "B")
        result.set_perf_data("license_capacity", capacity, "B")
        return result

    def check_search_peer(self, splunkd):
        status = splunkd.get_search_peer_status(self.options.search_peer)

        output = "Search peer is {}".format(status)
        return self.response_for_value(status, output, critical_value="Down", zabbix_ok="1", zabbix_critical="0")
        
    def check_concurrent_searches(self, splunkd):
        searches = len(list(splunkd.running_jobs))

        output = "{} searches are currently running".format(searches)
        result = self.response_for_value(searches, output)
        result.set_perf_data("searches", searches)
        return result

    def check_output(self, splunkd):
        status = splunkd.get_tcp_output_status(self.options.output)

        output = "{} is currently in status '{}'".format(self.options.output, status)
        return self.response_for_value(status, output, ok_value="connect_done", zabbix_ok="1", zabbix_critical="0")

if __name__ == "__main__":
    CheckSplunk().check().exit()
