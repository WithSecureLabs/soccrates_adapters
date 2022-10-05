# CSV based importing of facts and objects to the IMC

There were a number of cases in the Soccrates project where there was a need to process large and complex JSON reports about infrastructure to make them available in the IMC data model so other Socrrates components such as the ADG could take advantage of that data.

Example cases were firewall configurations and routing details contained in JSON configuration files and details about the way Active Directory had been configured in the infrastructure being protected.

As these JSON files vary a lot in their layout between different infrastructures, (e.g. firewall configuration files depend a lot on hardware providers), we elected to use an approach where the Soccrates components would consist of lightweight scripts using jq to extract the needed elements from the JSON and store those as CSV files.

Soccrates project has designed a data model which makes it possible to link the details stored in this file with other details such as vulnerabilities found on hosts in the network.
This data model is documented in the D3.3 report available at https://www.soccrates.eu/results/

As an example, let's assume a firewall configuration JSON file contains routing information embedded as an array of routes objects in the document, such as:

```
  "routes": [
	{
			"id": "10.255.129.0/24",
			"metric": 0,
			"nextHop": "10.255.129.1",
			"interface": "eth1",
			"routesTo": "10.255.129.0/24"
		}
        ]

```

In the jq command below, the "routesTo" facts in the JSON is extracted and stored in CSV format: the input JSON in this case contains an array of routes in a fairly flat structure. The first part of the command extracts all facts related to routing from the file and the second part just converts these into an easier to process CSV format.

```
jq  -r '[.routes[] | {"facttype":"routesTo", "source": .id,  "sourcetype": "route", "destination":.routesTo, "destinationtype": "ipv4Network", "factvalue":""}]' example-network.json | jq -r '(.[0] | keys_unsorted) as $keys | ([$keys] + map([.[ $keys[] ]])) []   | @csv'  >> example_imc_facts.csv

```
The output file contains facts which link a source to a destination object using a specified link type and a possible (in this case empty) fact value.
The CSV files produced follow a common format to specify either a fact which states that a certain object has a certain property or that two objects are connected by a specified relationship.

Once all the needed data has been extracted and stored in CSV format, a simple python program processes the CSV files and stores the specifed facts and relationships into the IMC data model in ACT platform using the ACT API.


## Processing the CSV files to the IMC

The repository contains a python program which can be used to read the CSV files generated as above and to submit them to ACT platform.

This program makes use of jq, to install jq in Ubuntu, use the following:

sudo apt update
sudo apt install jq

To run the component, a python3 environment is required and 2 extra packages need to be installed:

pip3 install act-api
pip3 install pyyaml

The ACT API is documented at https://github.com/mnemonic-no/act-api-python

A config.yaml file needs to be placed in the same directory as the adaptor and has the following entries:

act :  user name and password to the ACT DB where IMC data is stored.

A flag can be set in the file to make a dry run on the results, i.e. not write them to the ACT DB.

A debug flag is also possible to set to produce more verbose output.

```
python3 process_to_act.py
```

ACT API produces output during the run, detailing the facts which have been added to the database including the fact ids.

These can be checked from the ACT UI to verify that the graph produced is as expected.



