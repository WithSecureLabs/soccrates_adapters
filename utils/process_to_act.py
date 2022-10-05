"""
Util for reading CSV files containing objects and facts and inserting then into the ACT DB

This is a utility intended to make it easy to add batches of facts in CSV format to ACT database
in the scope of SOCCRATES project.


Copyright (c) 2022 WithSecure
See LICENSE for details

"""

import logging
import time
from http import HTTPStatus
import yaml
import requests
import sys
import csv
import os

import act.api  # for working with ACT DB

def setup_logging():
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
    logging.getLogger("urllib3").setLevel(logging.WARNING)  #noisy

    return logger


def read_settings():
    """ Read commonly used values """
    with open("config.yaml") as file:
        return yaml.full_load(file)


SETTINGS = read_settings()
LOGGER = setup_logging()

ACT_HANDLER = act.api.Act(
    SETTINGS["act"]["url"],
    user_id=SETTINGS["act"]["userid"],
    log_level="error",
    origin_name=SETTINGS["origin"]["name"],
    requests_common_kwargs={"auth": (SETTINGS["act"]["user"], SETTINGS["act"]["password"])},
)


def write_act_fact(fact_type, source_type, source_detail, dest_type, dest_detail, fact_value=None):
    """
    Write a fact to the ACT DB as needed. Facts are directional and connect 2 objects.
    :param: fact_type: Think of this as the label on the edge between the source and destination (e.g. runs)
    :param: source_type: The type of object the fact starts from, e.g. IPv4
    :param: source_detail: Details about the source such as unique identifier for that like IP
    :param: dest_type: Destination object type
    :param: dest_detail: Details to identify the target object for the fact.
    """
    LOGGER.info(
        "ACT\tFACT\ttype\t%s\tvalue\t%s\tsource\t%s\t\"%s\"\tdest\t%s\t\"%s\"",
        fact_type,
        fact_value,
        source_type,
        source_detail,
        dest_type,
        dest_detail,
    )
    if len(dest_detail)==0 or len(source_detail)==0:
        LOGGER.error("ACT Error: can't add to empty nodeids!")
        return
    if SETTINGS["act"]["writefacts"]:
        try:
            if fact_value is not None and len(fact_value)>0:
                ACT_HANDLER.fact(fact_type, fact_value).source(source_type, source_detail).destination(
                    dest_type, dest_detail
                ).add()
            else:
                ACT_HANDLER.fact(fact_type).source(source_type, source_detail).destination(
                    dest_type, dest_detail
                ).add()
        except act.api.base.ResponseError as resp_err:
            LOGGER.error("ACT Error %s", resp_err)


def write_act_prop(fact_type, source_type, source_detail, fact_detail):
    """
    Write property style objects to ACT
    Properties refer to a single object
    @param: fact_type: The type of fact, e.g. confidentialityImpact
    @param: source_type: Type of object to apply the fact to
    @param: source_detail: Unique identifer for the object e.g. IP
    @param: fact_detail: More details about the fact, e.g. CVSS score
    """
    LOGGER.info(
        "ACT\tPROP\tsource\t%s\t\"%s\"\ttype\t%s\t\"%s\"", source_type, source_detail, fact_type, fact_detail,
    )
    if SETTINGS["act"]["writefacts"]:
        try:
            ACT_HANDLER.fact(fact_type, fact_detail).source(source_type, source_detail).add()
        except act.api.base.ResponseError as resp_err:
            LOGGER.error("ACT Error %s", resp_err)


def load_file(filename):
    with open(filename) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if "factvalue" in row:
                write_act_fact(row['facttype'],row['sourcetype'],row['source'],row['destinationtype'],row['destination'],row['factvalue'])
            else:
                write_act_fact(row['facttype'],row['sourcetype'],row['source'],row['destinationtype'],row['destination'])

def load_propfile(filename):
    with open(filename) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if 'factdetail' in row and len(row['factdetail'])>1:
                write_act_prop(row['facttype'],row['sourcetype'],row['source'],row['factdetail'])


def main():
    """ Connect to ACT and process sharphound facts and properties """

    if SETTINGS["origin"]["setname"]:
        origin_name = SETTINGS["origin"]["name"]
        origin_trust = SETTINGS["origin"]["trust"]
        origin_description = SETTINGS["origin"]["descrption"]
        origin = ACT_HANDLER.origin(origin_name, origin_trust, origin_description)
        origin.add()

    # Use the below setting to save output to a file
    if SETTINGS["general"]["outfile"]:
        print("directing output to ", SETTINGS["general"]["outfile"])
        sys.stdout = sys.stderr = open(SETTINGS["general"]["outfile"], 'a')

    # add facts about firewall rules
    load_file("example_imc_facts.csv")

    # add properties about the objects for the IMC
    load_propfile("example_imc_properties.csv")


if __name__ == "__main__":
    try:
        main()
    except:
        LOGGER.exception("Lookup failed")
        raise
