# ACT DB adapter for WithSecure Elements Vulnerability Management

## Purpose

WithSecure Elements Vulnerability Management (earlier known as F-Secure Radar) is a vulnerability scanner for your whole network and all its assets.
For more details, including requesting demos and trial versions, visit https://www.withsecure.com/en/solutions/software-and-services/elements-vulnerability-management

The adapters and utlities in this repository were created as part of WithSecure participation in the EU Soccrates project https://www.soccrates.eu/ , specifically to populate the Infrastructure Data Model.
SOCCRATES has received funding from the European Union’s Horizon 2020 Research and Innovation program under Grant Agreement No. 833481 and work on this software was carried out using that funding.
The adapter processes scan results from the organizations into Objects and Facts according to the agreed schema for the Infrastructure Modelling Component in WP3.

Assets and vulnerabilities are written as Facts and Objects into the ACT DB provided by Mnemonic using the ACT API.

## Other use cases for this package

Customers of Elements VM who would like to visualize their infrastructure beyond the possibilities which Elements currently supports could use this adapter in conjunction with the ACT platform https://github.com/mnemonic-no/act-platform.

Also, the code could serve as an example for a company of how to fetch their Elements VM data and modify the data to formats and targets that the company uses locally (e.g., splunk or OpenCTI).


## Setup instructions

To run the adapter component, a python3.7 or newer environment is required and 2 extra packages need to be installed:

pip3 install act-api
pip3 install pyyaml


## Usage

The Elements VM/Radar API used is documented at https://api.radar.f-secure.com/apidoc/

The ACT API is documented at https://github.com/mnemonic-no/act-api-python

In order to use this adapter, API keys are needed for both of these APIs. The Elements VM API key will provide access to scan results and assets details for a target company associated with the API key.

A config.yaml file needs to be placed in the same directory as the adapter and has the following entries:

act: user name and password details for the ACT platform.

radar: api key IDs and Secrets, obtainable from WithSecure Elements Portal.

general: Debug settings & domain name setting to ensure fully qualified domain names are listed properly. Also a flag can be set in the file to make a dry run on the results, i.e. not write them to the ACT DB. VM Scans can produce large amounts of data, so the adapter can be configured to write its output to a dedicated file. This section also includes an option to restrict the adaptor to only fetch IP address and hostname information from the asset information in Radar, rather than also via discovery and thing scans. When using the adapter to pick up only the latest changes, it is recommended to have this setting as true, but if the full history of IPs seen in the network is needed, the setting should be set to false.

origin: The ACT database requires that data is labelled with the origin it relates to and the name of the origin can be set here.

To run the adaptor code execute the following:

```
python3 process_elementsvm_to_act.py
```

## Validating imported data

Debug logs from the adapter run should show details about the run such as the vulnerabilities reported or the asset host names detected in the most recent scans.

To verify that these have been imported correctly into the ACT DB, the ACT platform UI can be used to search for the named host names or CVE details and to verify that the data is connected as expected.


## Scan types

Elements VM solution provides a number of different ways to scan the target networks. The adapter is configured to fetch information about the following types of scans:

- Discovery Scans: Most useful for finding the IP address ranges which are being scanned in the network. Discovery scans also identify all host names and IPs seen in the target networks, but it is recommended to rely on the asset scans for fetching these, unless a full history is required. See the settings above for controlling this.

- Thing Scans: These scans return data from endpoints in the network running the Elements VM agent and contain more detailed software inventory details for those hosts as well as Active directory group membership details. As with Discovery scans, IP address allocations are available from here, but fetching these from the Asset scans is recommended unless a full history is needed.

- Asset Scans: From the asset related endpoints on the Elements VM API, we pick up the most detailed information about the hosts seen in network scans carried out by Elements. Details such as host names and IPs seen during the most recent scans are picked up the adapter from here. Also CIA details are fetched.

- System scans: These scans provide the important details about which vulnerabilities were seen on which hosts. Details about the vulnerabilities such as severity are stored as facts using data from the system scan endpoints.

- Web Scans: These scans target finding open ports on hosts in the network so vulnerabilities from here are stored as facts to IMC.
