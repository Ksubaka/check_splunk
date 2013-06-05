import datetime
import requests
import time

import xml.etree.ElementTree as ET


class TimeoutError(Exception):
    pass


def parse_skey(skey):
    if len(skey) == 0:
        # Just a value
        value = skey.text
    else:
        child = skey[0] # Should only have one child
        if child.tag == "{http://dev.splunk.com/ns/rest}dict":
            value = parse_sdict(child)
        elif child.tag == "{http://dev.splunk.com/ns/rest}list":
            value = parse_slist(child)
    return (skey.get("name"), value)


def parse_sdict(sdict):
    parsed = dict()
    for skey in sdict.iterfind("./{http://dev.splunk.com/ns/rest}key"):
        (k,v) = parse_skey(skey)
        parsed[k] = v
    return parsed


def parse_slist(slist):
    parsed = list()
    for child in slist:
        parsed.append(child.text)
    return parsed


class SplunkServer(object):
    def __init__(self, hostname, username, password, port=8089, use_ssl=True, timeout=30, **kwargs):
        self.session = requests.Session()
        self.server = "%s://%s:%d" % ("https" if use_ssl else "http", hostname, int(port))
        self.session.auth = (username, password)
        self.cache = dict()
        self.timeout = int(timeout)

    def _get_url(self, url, cache=True, **kwargs):
        if "urls" not in self.cache:
            self.cache["urls"] = dict()

        url = url.format(**kwargs)
        if url in self.cache["urls"]:
            return self.cache["urls"][url]
        url = "%s%s" % (self.server, url)
        r = self.session.get(url, verify=False)
        if cache:
            self.cache["urls"][url] = ET.fromstring(r.text)
        return self.cache["urls"][url]

    def _run_search(self, search, as_list=False, **kwargs):
        url = "{}{}".format(self.server, "/services/search/jobs")
        data = dict()
        data.update(kwargs)
        data["search"] = "search {}".format(search)

        # Get the search ID
        r = self.session.post(url, data=data, verify=False)
        xml = ET.fromstring(r.text)
        #print r.text
        sid = xml.find("./sid").text

        # Wait for search to complete
        url = "{}{}".format(self.server, "/services/search/jobs/{}/results".format(sid))

        timeout = datetime.datetime.now() + datetime.timedelta(seconds=self.timeout)
        while datetime.datetime.now() < timeout:
            r = self.session.get(url)
            if r.status_code == 200:
                break
            time.sleep(1)

        # Have results
        if r.status_code == 204:
            raise TimeoutError

        xml = ET.fromstring(r.text)
        def generate():
            for result in xml.iterfind("./result"):
                r = dict()
                for field in result.iterfind("./field"):
                    r[field.get("k")] = field.find("./value/text").text
                yield r

        if as_list:
            return list(generate())
        else:
            return generate()

    @property
    def isTrial(self):
        root = self._get_url("/servicesNS/nobody/system/server/info")

        sdict = root.find("./{http://www.w3.org/2005/Atom}entry/{http://www.w3.org/2005/Atom}content/{http://dev.splunk.com/ns/rest}dict")
        skey = sdict.find("./{http://dev.splunk.com/ns/rest}key[@name='isTrial']")

        return bool(skey.text == "0")

    @property
    def isFree(self):
        root = self._get_url("/servicesNS/nobody/system/server/info")

        sdict = root.find("./{http://www.w3.org/2005/Atom}entry/{http://www.w3.org/2005/Atom}content/{http://dev.splunk.com/ns/rest}dict")
        skey = sdict.find("./{http://dev.splunk.com/ns/rest}key[@name='isFree']")

        return bool(skey.text == "0")

    @property
    def licenses(self):
        root = self._get_url("/services/licenser/licenses")
        for entry in root.iterfind("./{http://www.w3.org/2005/Atom}entry"):
            sdict = entry.find("./{http://www.w3.org/2005/Atom}content/{http://dev.splunk.com/ns/rest}dict")
            yield parse_sdict(sdict)

    @property
    def valid_enterprise_licenses(self):
        for license in self.licenses:
            if license["status"] == "VALID" and license["type"] == "enterprise":
                yield license

    @property
    def license_pools(self):
        root = self._get_url("/services/licenser/pools")
        for entry in root.iterfind("./{http://www.w3.org/2005/Atom}entry"):
            sdict = entry.find("./{http://www.w3.org/2005/Atom}content/{http://dev.splunk.com/ns/rest}dict")
            yield parse_sdict(sdict)

    @property
    def jobs(self):
        root = self._get_url("/services/search/jobs")
        for entry in root.iterfind("./{http://www.w3.org/2005/Atom}entry"):
            sdict = entry.find("./{http://www.w3.org/2005/Atom}content/{http://dev.splunk.com/ns/rest}dict")
            yield parse_sdict(sdict)

    @property
    def running_jobs(self):
        for job in self.jobs:
            statuses = [ bool(int(job[k])) for k in ("isDone", "isFailed", "isFinalized",) ]
            if any(statuses):
                continue
            yield job

    @property
    def search_peers(self):
        root = self._get_url("/services/search/distributed/peers")
        for entry in root.iterfind("./{http://www.w3.org/2005/Atom}entry"):
            sdict = entry.find("./{http://www.w3.org/2005/Atom}content/{http://dev.splunk.com/ns/rest}dict")
            yield parse_sdict(sdict)

    @property
    def tcp_outputs(self):
        root = self._get_url("/services/data/outputs/tcp/server")
        for entry in root.iterfind("./{http://www.w3.org/2005/Atom}entry"):
            sdict = entry.find("./{http://www.w3.org/2005/Atom}content/{http://dev.splunk.com/ns/rest}dict")
            yield parse_sdict(sdict)

    @property
    def cluster_config(self):
        root = self._get_url("/services/cluster/config")
        return parse_sdict(root.find("./{http://www.w3.org/2005/Atom}entry[1]/{http://www.w3.org/2005/Atom}content/{http://dev.splunk.com/ns/rest}dict"))

    @property
    def cluster_buckets(self):
        root = self._get_url("/services/cluster/master/buckets")
        for entry in root.iterfind("./{http://www.w3.org/2005/Atom}entry"):
            sdict = entry.find("./{http://www.w3.org/2005/Atom}content/{http://dev.splunk.com/ns/rest}dict")
            yield parse_sdict(sdict)

    @property
    def cluster_peers(self):
        root = self._get_url("/services/cluster/master/peers")
        for entry in root.iterfind("./{http://www.w3.org/2005/Atom}entry"):
            sdict = entry.find("./{http://www.w3.org/2005/Atom}content/{http://dev.splunk.com/ns/rest}dict")
            yield parse_sdict(sdict)

    def get_pool_info(self, pool):
        root = self._get_url("/servicesNS/nobody/system/licenser/pools/{pool_name}", pool_name=pool)
        sdict = root.find("./{http://www.w3.org/2005/Atom}entry/{http://www.w3.org/2005/Atom}content/{http://dev.splunk.com/ns/rest}dict")
        return parse_sdict(sdict)

    def get_license_pool_licenses(self, pool):
        stack_id = self.get_pool_info(pool)["stack_id"]

        licenses = list()
        for license in self.valid_enterprise_licenses:
            if license["stack_id"] == stack_id:
                licenses.append(license)
        return licenses

    def get_license_pool_used_bytes(self, pool):
        return int(self.get_pool_info(pool)["used_bytes"])

    def get_license_pool_capacity(self, pool):
        return sum([ int(l["quota"]) for l in self.get_license_pool_licenses(pool) ])

    def get_index_info(self, index):
        root = self._get_url("/servicesNS/nobody/system/data/indexes/{index_name}", index_name=index)
        sdict = root.find("./{http://www.w3.org/2005/Atom}entry/{http://www.w3.org/2005/Atom}content/{http://dev.splunk.com/ns/rest}dict")
        return parse_sdict(sdict)

    def get_index_used_bytes(self, index):
        return int(self.get_index_info(index)["currentDBSizeMB"])

    def get_index_capacity(self, index):
        return int(self.get_index_info(index)["maxTotalDataSizeMB"])

    def get_search_peer_info(self, peer):
        root = self._get_url("/services/search/distributed/peers/{peer_name}", peer_name=peer)
        sdict = root.find("./{http://www.w3.org/2005/Atom}entry/{http://www.w3.org/2005/Atom}content/{http://dev.splunk.com/ns/rest}dict")
        return parse_sdict(sdict)

    def get_tcp_output_info(self, output):
        root = self._get_url("/servicesNS/nobody/cwru_all_deployment_outputs/data/outputs/tcp/server/{output_name}", output_name=output)
        sdict = root.find("./{http://www.w3.org/2005/Atom}entry/{http://www.w3.org/2005/Atom}content/{http://dev.splunk.com/ns/rest}dict")
        return parse_sdict(sdict)

    def get_cluster_peer_info(self, peer):
        return (_peer for _peer in self.cluster_peers if _peer["label"] == peer).next()

    def get_license_pool_usage(self, pool):
        used = self.get_license_pool_used_bytes(pool)
        capacity = self.get_license_pool_capacity(pool)
        pct_used = int(used * 100 / capacity)
        return (used, capacity, pct_used)

    def get_index_usage(self, index):
        used = self.get_index_used_bytes(index)
        capacity = self.get_index_capacity(index)
        pct_used = int(used * 100 / capacity)
        return (used, capacity, pct_used)

    def get_index_latency(self, index, span=30):
        search = "index={} | eval latency=round((_indextime - _time),2) | stats avg(latency) AS avglat | eval avglat=round(avglat,2)".format(index)
        earliest_time = datetime.datetime.now() - datetime.timedelta(minutes=span)
        return float(self._run_search(search, as_list=True, earliest_time=earliest_time.isoformat())[0]["avglat"])

    def get_search_peer_status(self, peer):
        return self.get_search_peer_info(peer)["status"]

    def get_tcp_output_status(self, output):
        return self.get_tcp_output_info(output)["status"]

    def get_cluster_peer_status(self, peer):
        return self.get_cluster_peer_info(peer)["status"]
