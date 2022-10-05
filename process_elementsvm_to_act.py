"""
 Simple adapter for extracting Soccrates IMC data model related values from
 WithSecure Elements Vulnerability Management (also referred to below as Radar)
 and posting them to ACT DB via public APIs of both systems.

 The API to Elements VM is documented https://api.radar.f-secure.com/apidoc/

Copyright (c) 2022 WithSecure
See LICENSE for details

"""

import json
import logging
import time
import ipaddress
import os.path
from http import HTTPStatus
import sys
import yaml
import requests

import act.api


def setup_logging():
    """Log format and silencing"""
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=os.environ.get("LOG_LEVEL", "INFO"),
            datefmt="%Y-%m-%dT%H:%M:%S",
            format="%(asctime)s.%(msecs)d %(levelname)s %(name)s %(message)s",
        )
    logger = logging.getLogger()
    logger.setLevel(os.environ.get("LOG_LEVEL", "DEBUG"))
    if SETTINGS["general"]["loglevel"]:
        logger.setLevel(os.environ.get("LOG_LEVEL", SETTINGS["general"]["loglevel"]))
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    return logger


def read_settings():
    """Read commonly used values"""
    with open("config.yaml") as file:
        return yaml.full_load(file)


SETTINGS = read_settings()
LOGGER = setup_logging()

# set the act password details in the config file!
ACT_HANDLER = act.api.Act(
    SETTINGS["act"]["url"],
    user_id=SETTINGS["act"]["userid"],
    log_level="error",
    origin_name=SETTINGS["origin"]["name"],
    requests_common_kwargs={"auth": (SETTINGS["act"]["user"], SETTINGS["act"]["password"])},
)
# set the Radar / Elements VM api key details in the config file!
RADAR_URL = SETTINGS["radar"]["url"]
RADAR_HEADERS = {
    "content-type": "application/json",
    "ApiAccessKey": SETTINGS["radar"]["apikey"],
    "ApiSecretKey": SETTINGS["radar"]["apisecretkey"],
}

SCANNED_RANGES = []  # For caching network ranges being scanned
KNOWN_ASSIGNS = {}  # For caching known IP<->hostname assignments

# placeholders for CVE -> Vuln SW mappings
KNOWN_HVULNSW = {}
KNOWN_MVULNSW = {}
KNOWN_LVULNSW = {}

ASSET_HOSTS = {}


def write_act_fact(fact_type, source_type, source_detail, dest_type, dest_detail):
    """
    Write a fact to the ACT DB as needed. Facts are directional and connect 2 objects.
    :param: fact_type: Think of this as the label on the edge between src/dst (e.g. runs)
    :param: source_type: The type of object the fact starts from, e.g. IPv4
    :param: source_detail: Details about the source such as unique identifier for that like IP
    :param: dest_type: Destination object type
    :param: dest_detail: Details to identify the target object for the fact.
    """
    LOGGER.info(
        'ACT\tFACT\ttype\t%s\tsource\t%s\t"%s"\tdest\t%s\t"%s"',
        fact_type,
        source_type,
        source_detail,
        dest_type,
        dest_detail,
    )
    if SETTINGS["act"]["writefacts"]:
        try:
            ACT_HANDLER.fact(fact_type).source(source_type, source_detail).destination(
                dest_type, dest_detail
            ).add()
        except act.api.base.ResponseError as resp_err:
            LOGGER.error("ACT Error %s", resp_err)


def write_act_prop(fact_type, source_type, source_detail, fact_detail):
    """
    Write property style facts to ACT
    Properties refer to a single object
    @param: fact_type: The type of fact, e.g. confidentialityImpact
    @param: source_type: Type of object to apply the fact to
    @param: source_detail: Unique identifer for the object e.g. IP
    @param: fact_detail: More details about the fact, e.g. CVSS score
    """
    LOGGER.info(
        'ACT\tPROP\tsource\t%s\t"%s"\ttype\t%s\t"%s"',
        source_type,
        source_detail,
        fact_type,
        fact_detail,
    )
    if SETTINGS["act"]["writefacts"]:
        try:
            ACT_HANDLER.fact(fact_type, fact_detail).source(source_type, source_detail).add()
        except act.api.base.ResponseError as resp_err:
            LOGGER.error("ACT Error %s", resp_err)


def get_vuln_pkg(host_name, risk_level):
    """
    Helper to find known vuln packages on the host at this risk level based on earler asset scan

    @param: host_name: Host name vulnerable packages are requested for
    @param: risk_level: Risk level of the vulnerability
    """
    vuln_sw = ""
    # Did we earlier find vulnerable libs on the host -> list here
    if risk_level == "Low":
        if KNOWN_LVULNSW.get(host_name):
            vuln_sw = KNOWN_LVULNSW.get(host_name)
    elif risk_level == "Medium":
        if KNOWN_MVULNSW.get(host_name):
            vuln_sw = KNOWN_MVULNSW.get(host_name)
    elif risk_level == "High":
        if KNOWN_HVULNSW.get(host_name):
            vuln_sw = KNOWN_HVULNSW.get(host_name)
    return vuln_sw


def radar_req(radar_url):
    """
    Make a GET request to the specified radar endpoint.
    In error cases, log error and return empty json
    @param: radar_url: target URL for the request
    """
    resp = requests.get(radar_url, headers=RADAR_HEADERS)
    if resp.status_code != HTTPStatus.OK:
        LOGGER.debug("Issue with %s", radar_url)
        LOGGER.error(resp.text)
        return "{}"
    return resp.text


def radar_post(radar_url, post_data):
    """
    Make a POST request to the specified radar endpoint.
    In error cases, log error and return empty json
    :param radar_url: where to send the request
    :param post_data: the actual data to be sent
    """
    resp = requests.post(radar_url, headers=RADAR_HEADERS, json=post_data)
    if resp.status_code != HTTPStatus.OK:
        LOGGER.error(
            "POST ISSUE ERROR %s %s with content=%s",
            radar_url,
            str(resp.status_code),
            str(resp.content),
        )
        return "{}"
    return resp.text


def process_system_scans():
    """
    system scans are the results of possible exploits being tried against hosts
    (compared to discovery scans which are more or less nmap runs)
    Process assets from each system scan to see which vulns happen on which hosts..
    This is the main source of CVE information during the scan
    """
    LOGGER.debug("Processing System Scans..")

    # Process scangroup -> scan -> findings -> vulnlist -> vuln cve list
    for scangroup in json.loads(radar_req(RADAR_URL + "scangroups/simple")):
        LOGGER.debug("Process group %s id %s", scangroup.get("Name"), scangroup.get("Id"))

        # Start on the scangroup directly: look at system scans first
        for scanmeta in json.loads(
                radar_req(RADAR_URL + "scangroups/" + scangroup.get("Id") + "/systemscans")
        ):
            LOGGER.debug("System Scan Name %s Id %s", scanmeta.get("Name"), scanmeta.get("Id"))
            LOGGER.debug("System Scan Host %s", scanmeta.get("Hostname"))
            LOGGER.debug("System Scan Time %s", scanmeta.get("ScanLastCompleted"))

            scan_id = scanmeta.get("Id")
            # for each system scan, find out if it reported vulnerabilities
            # for any of the assets collected
            vlist = "/reports/latest/vulnerabilitiesandfindings/withStartIndex/0/andPageSize/1000"
            for asset_host, asset_id in ASSET_HOSTS.items():
                # now get the details for each scan, including vulnerabilities
                scan_post_data = {}
                scan_post_data["ScanId"] = scan_id
                scan_post_data["Findings"] = "All"

                findingslist = json.loads(
                    radar_post(
                        RADAR_URL
                        + "assets/"
                        + asset_id
                        + vlist,
                        scan_post_data
                    )
                )
                LOGGER.debug(
                    "findings list has %d entries for scan %s and asset %s",
                    len(findingslist),
                    scan_id,
                    asset_id,
                )
                for finding in findingslist.get("Items", {}):
                    # There can be many items so a sleep is recommended here
                    time.sleep(1)
                    vuln_id = finding.get("PluginGuidId")
                    # with this pull out all available details
                    vuln_url = RADAR_URL + "vulnerabilities/systemscan/" + vuln_id + "/detailed"
                    vresp = requests.get(vuln_url, headers=RADAR_HEADERS)
                    if vresp.status_code != HTTPStatus.OK:
                        LOGGER.error(vresp.text)
                        continue
                    vuln_det = json.loads(vresp.text)
                    # Depending on
                    if vuln_det.get("RiskLevel", "Information") != "High":
                        continue
                    LOGGER.debug("Vuln Cat  = %s", str(vuln_det.get("VulnerabilityCategory")))
                    LOGGER.debug("Vuln Desc  = %s", str(vuln_det.get("Synopsis")))

                    for cve_ref in vuln_det.get("CVEReferences", []):
                        # for this case :  Radar found NO LIB having the vuln but we
                        # know the host has it use the category information from the VULN
                        # to mark that the asset has a lib causing the problem
                        vuln_cat = str(vuln_det.get("VulnerabilityCategory"))
                        if vuln_cat == "Generic":
                            fake_vuln_sw = str(vuln_det.get("Synopsis"))
                        else:
                            fake_vuln_sw = vuln_cat

                        write_act_fact("runs", "host", asset_host, "software", fake_vuln_sw)
                        write_act_fact(
                            "affects",
                            "vulnerability",
                            cve_ref.get("Name"),
                            "software",
                            fake_vuln_sw,
                        )

                        # CVSS : add as a score
                        if vuln_det.get("CVSSBaseScore", "") != "":
                            write_act_prop(
                                "score",
                                "vulnerability",
                                cve_ref.get("Name"),
                                vuln_det.get("CVSSBaseScore", ""),
                            )
                        time.sleep(1)  # don't flood radar!
                        LOGGER.debug("VULN Affects asset host %s id %s", asset_host, asset_id)
                        LOGGER.debug("Vuln Desc  = %s", str(vuln_det.get("Name", "")))

    return HTTPStatus.OK


def process_web_scans():
    """
    Process the results of internet scans.
    """
    LOGGER.debug("Processing Web Scans..")
    # begin by getting the array of scan groups in the target
    resp = requests.get(RADAR_URL + "scangroups/simple", headers=RADAR_HEADERS)
    if resp.status_code != HTTPStatus.OK:
        LOGGER.error(resp.text)
        return resp.status_code
    scangroups = json.loads(resp.text)
    for scangroup in scangroups:
        groupid = scangroup.get("Id")
        LOGGER.debug("Process group %s id = %s", scangroup.get("Name"), groupid)

        # Let's start on the scangroup directly: look at web scans first
        resp = requests.get(
            RADAR_URL + "scangroups/" + groupid + "/webscans", headers=RADAR_HEADERS
        )
        if resp.status_code != HTTPStatus.OK:
            LOGGER.error(resp.text)
            return resp.status_code
        if resp.text == "[]":
            LOGGER.debug("No Web Scan results")
        scanlist = json.loads(resp.text)
        for scanmeta in scanlist:
            LOGGER.debug("Scanid %s", scanmeta.get("Id"))
            LOGGER.debug("Scanname %s", scanmeta.get("Name"))
            LOGGER.debug("Scanhost %s", scanmeta.get("Hostname"))
            LOGGER.debug("Scantime %s", scanmeta.get("ScanLastCompleted"))
            # now get the details for each scan, maybe get the vulns too?
            findings_url = (
                RADAR_URL
                + "webscans/"
                + scanmeta.get("Id")
                + "/reports/latest/vulnerabilitiesandfindings/withstartindex/0/andpagesize/1000"
            )
            resp = requests.post(findings_url, headers=RADAR_HEADERS, data="")
            if resp.status_code != HTTPStatus.OK:
                LOGGER.error(resp.text)
                return resp.status_code
            findingslist = json.loads(resp.text)
            for finding in findingslist.get("Items"):
                # vuln details
                vuln_id = finding.get("PluginGuidId")
                # with this pull out all available details
                vuln_url = RADAR_URL + "vulnerabilities/webscan/" + vuln_id + "/detailed"
                vresp = requests.get(vuln_url, headers=RADAR_HEADERS)
                if vresp.status_code != HTTPStatus.OK:
                    LOGGER.error(vresp.text)
                    return vresp.status_code
                vuln_det = json.loads(vresp.text)
                # Record a fact about the vulnerability having a score
                if vuln_det.get("CVSSBaseScore", "") != "":
                    write_act_prop(
                        "score",
                        "vulnerability",
                        vuln_det.get("ReferenceId", ""),
                        vuln_det.get("CVSSBaseScore", ""),
                    )
                time.sleep(1)

    return HTTPStatus.OK


def process_host_sw(host_sw, asset_host_name):
    """Record SW on host and vulns associated with SWs"""
    # If we find SW which a labelled vuln
    if (
            host_sw["VulnerabilitiesHigh"]
            or host_sw["VulnerabilitiesMedium"]
            or host_sw["VulnerabilitiesLow"]
    ):
        sw_id = host_sw["Name"] + ":" + host_sw["Version"]
        LOGGER.debug("VULN found in SW %s", sw_id)
        write_act_fact("runs", "host", asset_host_name, "software", sw_id)
        # When we get vuln reports later from the scan results
        # we need to pull out this SWID and store
        if host_sw["VulnerabilitiesHigh"]:
            KNOWN_HVULNSW[asset_host_name] = sw_id
        if host_sw["VulnerabilitiesMedium"]:
            KNOWN_MVULNSW[asset_host_name] = sw_id
        if host_sw["VulnerabilitiesLow"]:
            KNOWN_LVULNSW[asset_host_name] = sw_id
    return True


def process_assets():
    """Extracts available objects and facts from the asset related endpoints on the VM API"""
    LOGGER.debug("Processing Assets")

    asset_available = radar_req(RADAR_URL + "assets/any")
    if asset_available != "true":
        LOGGER.debug("No assets")
        return HTTPStatus.OK
    LOGGER.debug("Get asset list")
    asset_resp = radar_post(RADAR_URL + "assets/withstartindex/0/andpagesize/100", "")
    asset_items = json.loads(asset_resp).get("Items", {})
    for asset in asset_items:
        asset_host_name = asset.get("Hostname", "").lower()
        # ensure host names are FQDNs
        if (
                SETTINGS["general"]["domain"] not in asset_host_name
                and ".compute.internal" not in asset_host_name
        ):
            asset_host_name = asset_host_name + SETTINGS["general"]["domain"]

        asset_host_ip = asset.get("IpAddress", "")
        # Not always available, but when it is, prefer it over hostname
        if "Id" in asset:
            ASSET_HOSTS[asset_host_name] = asset.get("Id")
        LOGGER.debug("Hostname = %s", asset_host_name)
        LOGGER.debug("Id = %s", asset.get("Id", ""))
        LOGGER.debug("Friendlyname = %s", asset.get("FriendlyName", ""))
        LOGGER.debug("IpAddress = %s", asset_host_ip)
        LOGGER.debug("Mac = %s ", str(asset.get("MacAddress", "")))
        LOGGER.debug("OS = %s", asset.get("OperatingSystem", ""))
        LOGGER.debug("Domainname = %s", asset.get("DomainName", ""))

        if len(asset_host_name) < 2:  # final sanity check to decide if we fall back to IP
            asset_host_name = asset_host_ip

        # add the assigned To facts for these objects
        write_act_fact("assignedTo", "ipv4", asset_host_ip, "host", asset_host_name)

        # also maintain a lookup to know which hostnames are in use at which IPs
        # in case mappings are needed elsewhere
        KNOWN_ASSIGNS[asset_host_ip] = asset_host_name
        # is this in one of the known CIDRs being scanned (based on Radar defs?)
        # if so create a memberof connection
        for ip_nw in SCANNED_RANGES:
            if ipaddress.ip_address(asset_host_ip) in ip_nw:
                LOGGER.debug("found a known network %s", str(ip_nw))
                # store fact to ACT about memberOf
                write_act_fact("memberOf", "ipv4", asset_host_ip, "ipv4Network", str(ip_nw))

        # ACT fact to indicate the OS running on the host
        asset_os = asset.get("OperatingSystem", "")
        if asset_os:
            write_act_fact("runs", "host", asset_host_name, "software", asset_os)
            write_act_prop("category", "software", asset_os, "os")

        # Hosts can be categorized as clients
        write_act_prop("category", "host", asset_host_name, "client")

        # Keep the friendly name for the hosts
        if asset.get("FriendlyName"):
            write_act_prop("name", "host", asset_host_name, asset.get("FriendlyName").lower())
        else:
            write_act_prop("name", "host", asset_host_name, asset_host_name)

        # dig a bit to get CIA info, these are set in Elements VM UI to indicate host importance
        asset_detail = json.loads(radar_req(RADAR_URL + "assethosts/asset/ " + asset.get("Id", "")))
        asset_detail_c = asset_detail.get("Confidentiality", 0)
        asset_detail_i = asset_detail.get("Integrity", 0)
        asset_detail_a = asset_detail.get("Availability", 0)
        LOGGER.debug("CIA = %d %d %d", asset_detail_c, asset_detail_i, asset_detail_a)
        if asset_detail_c > 0:
            write_act_prop("confidentialityImpact", "host", asset_host_name, asset_detail_c)
        if asset_detail_i > 0:
            write_act_prop("integrityImpact", "host", asset_host_name, asset_detail_i)
        if asset_detail_a > 0:
            write_act_prop("availabilityImpact", "host", asset_host_name, asset_detail_a)

        # get the installed software list for the asset
        post_params = {
            "AssetHostId": asset.get("AssetHostId", ""),
            "categoryName": "assets/installedsoftware",
            "SortPrimary": "Name",
        }

        # get all available unique identifier about the id:d software : CPEs if poss
        host_sw_list = json.loads(
            radar_post(
                RADAR_URL + "assets/installedsoftware/withStartIndex/0/andPageSize/1000",
                post_params,
            )
        )
        for host_sw in host_sw_list.get("Items", {}):
            process_host_sw(host_sw, asset_host_name)
    return HTTPStatus.OK


def process_discovery_id(disco_id, ip_range):
    """Run through the list of disovery IDs and process details"""
    disco_scan_url = (
        RADAR_URL
        + "discoveryscans/"
        + disco_id
        + "/reports/latest/hosts/withStartIndex/0/andPageSize/100"
    )
    resp = requests.post(disco_scan_url, headers=RADAR_HEADERS, data="")
    if resp.status_code != HTTPStatus.OK:
        LOGGER.error(resp.text)
        return resp.status_code
    disco_host_list = json.loads(resp.text)
    disco_host_items = disco_host_list.get("Items")
    for disco_host in disco_host_items:
        disco_host_ip = disco_host["IPAddress"]
        disco_host_name = disco_host["Hostname"].lower()
        if disco_host_name != "":  # not useful
            write_act_fact("assignedTo", "ipv4", disco_host_ip, "host", disco_host_name)
            KNOWN_ASSIGNS[disco_host_ip] = disco_host_name
            write_act_fact("memberOf", "ipv4", disco_host_ip, "ipv4Network", str(ip_range))
            disco_os = disco_host.get("OperatingSystem", "")
            if disco_os and disco_os != "[Linux]":  # not helpful, more useful from assets api
                write_act_fact("runs", "host", disco_host_name, "software", disco_os)
                write_act_prop("category", "software", disco_os, "os")
    return True


def process_discovery_scans():
    """Process the set of discovery scans set up to find CIDRS in use"""

    LOGGER.debug("Discovery scans")
    dscan_url = RADAR_URL + "discoveryscans/any"
    resp = requests.get(dscan_url, headers=RADAR_HEADERS)
    if resp.status_code != HTTPStatus.OK:
        LOGGER.error(resp.text)
        return resp.status_code
    if resp.text != "true":
        LOGGER.error("No Discovery scans")
        return resp.status_code

    disco_url = RADAR_URL + "discoveryscans/withstartindex/0/andpagesize/10"
    resp = requests.post(disco_url, headers=RADAR_HEADERS, data="")
    if resp.status_code != HTTPStatus.OK:
        LOGGER.error(resp.text)
        return resp.status_code

    disco_list = json.loads(resp.text)
    disco_items = disco_list.get("Items")
    for disco in disco_items:
        LOGGER.debug("Name=%s", disco["Name"])
        LOGGER.debug("Range=%s", disco["Range"])
        for drange in disco["Range"].split(","):
            SCANNED_RANGES.append(ipaddress.ip_network(drange))
        LOGGER.debug("ReportId=%s", disco["LastReportId"])
        LOGGER.debug("ScanLastCompleted %s", disco["ScanLastCompleted"])
        LOGGER.debug("********************")

        # Depending on conf, i.e. is there a preference to rely only on assets for IPs,hosts
        if not SETTINGS["general"]["ipsonlyfromassets"]:
            disco_id = disco["Id"]
            ip_ranges = disco["Range"].split(",")
            for ip_range in ip_ranges:
                process_discovery_id(disco_id, ip_range)

    return HTTPStatus.OK


def process_thing_scans():
    """
    Process the data from Radar Endpoint Agent scans.
    This captures for instance Active Directory Group memberships of hosts.
    Also pushes to ACT facts related to the software running on hosts.
    """

    LOGGER.debug("REA scans")
    thing_url = RADAR_URL + "things/withStartIndex/0/andPageSize/50"
    resp = requests.post(thing_url, headers=RADAR_HEADERS)
    if resp.status_code != HTTPStatus.OK:
        LOGGER.error(resp.status_code)
        LOGGER.error(resp.text)
        LOGGER.error(RADAR_HEADERS)
        LOGGER.error(thing_url)
        return resp.status_code

    thing_list = json.loads(resp.text)
    thing_items = thing_list.get("Items")
    for thing in thing_items:
        asset_host_name = thing.get("Hostname").lower()
        if asset_host_name != "" and not SETTINGS["general"]["ipsonlyfromassets"]:
            write_act_fact(
                "assignedTo", "ipv4", thing.get("IPAddress", ""), "host", asset_host_name
            )

        if "AdGroupName" in thing and thing["AdGroupName"] != "":
            if asset_host_name != "":
                write_act_fact("memberOf", "host", asset_host_name, "group", thing["AdGroupName"])
            else:
                if not SETTINGS["general"]["ipsonlyfromassets"]:
                    write_act_fact(
                        "memberOf",
                        "ipv4",
                        thing.get("IPAddress", ""),
                        "group",
                        thing["AdGroupName"],
                    )
        asset_os = thing.get("OperatingSystem")
        if asset_os:
            write_act_fact("runs", "host", asset_host_name, "software", asset_os)
            write_act_prop("category", "software", asset_os, "os")

    return HTTPStatus.OK


def main():
    """Connect to ACT and publish data fetched from Elements VM API"""

    # Use the below setting to save output to a file
    if SETTINGS["general"]["outfile"]:
        sys.stdout = sys.stderr = open(SETTINGS["general"]["outfile"], "a")

    # If needed set up ACT data origin details:  this is only needed once on empty DBs
    # so comment out from the config file once the origin has been added

    if SETTINGS["origin"]["setname"]:
        origin_name = SETTINGS["origin"]["name"]
        origin_trust = SETTINGS["origin"]["trust"]
        origin_description = SETTINGS["origin"]["descrption"]
        origin = ACT_HANDLER.origin(origin_name, origin_trust, origin_description)
        origin.add()

    process_discovery_scans()  # get facts about subnets and IP allocations (if configured)
    process_thing_scans()  # get more details about hosts, e.g., name, ADGroup, IPs (if configured)

    # Fetch vulnerability details from different available endpoints
    # assets are assumed to be master data for IP address allocations.
    if process_assets() == HTTPStatus.OK:
        process_system_scans()
        process_web_scans()


if __name__ == "__main__":
    try:
        main()
    except:
        LOGGER.exception("Lookup failed")
        raise
