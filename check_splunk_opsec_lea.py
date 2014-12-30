#!/usr/bin/env python

from splunk import ApiError,SplunkServer

import datetime
import pynagios



class CheckSplunkOpsecLea(pynagios.Plugin):
    username = pynagios.make_option("-U", type="string", help="Username used to log into Splunk")
    password = pynagios.make_option("-P", type="string", help="Password used to log into Splunk")
    port = pynagios.make_option("-p", type="int", default=8089, help="splunkd Port on server, default 8089")
    use_ssl = pynagios.make_option("-n", action="store_false", default=True, help="Disable HTTPS (use http)")
    entity = pynagios.make_option("--entity", type="string", help="Name of OPSEC entity to check")

    def check(self):
        splunkd = SplunkServer(self.options.hostname, self.options.username, self.options.password, self.options.port, self.options.use_ssl)
        try:
            root = splunkd._get_url("/servicesNS/nobody/Splunk_TA_opseclea_linux22/opsec/entity_log_status/{0}".format(self.options.entity))
        except ApiError as e:
            return pynagios.Response(pynagios.CRITICAL, str(e))
        sdict = root.find("./{http://www.w3.org/2005/Atom}entry/{http://www.w3.org/2005/Atom}content/{http://dev.splunk.com/ns/rest}dict")
        skey = sdict.find("./{http://dev.splunk.com/ns/rest}key[@name='last_log_update_timestamp']")

        last_updated_at = datetime.datetime.strptime(skey.text, "%Y-%m-%dT%H:%M:%SZ")
        now = datetime.datetime.utcnow()

        delta = now - last_updated_at
        return self.response_for_value(delta.seconds, "Last updated {0} seconds ago".format(delta.seconds))

CheckSplunkOpsecLea().check().exit()
