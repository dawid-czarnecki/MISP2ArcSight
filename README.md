README
======
# MISP to ArcSight ESM Active Lists integration tool

**Latest release**: 1.0<br/>
**License**: GNU GPL

MISP2ArcSight is a tool to send MISP attributes to ArcSight ESM Active Lists.<br/>
MISP2ArcSight allows you to:
* filter only specific attributes
* map specific fields in MISP to your custom ArcSight active list
* modify attributes on the fly
* prioritize organizations

## Requirements
* simplejson
* requests
* pymisp
* pyyaml
* pyasesm

```bash
pip3 install simplejson requests pymisp pyyaml pyasesm
```

If you cannot find pyasesm library run:
```bash
git clone https://github.com/dawid-czarnecki/MISP2ArcSight/pyasesm
cd pyasesm
pip3 install .
```

## Installation
There is no additional installation needed.

## Usage
There are a few files which influence the behavior of the tool and needs to be prepare before using it. All resides in configs directory.
* config.yaml - Main configuration file with URLs and credentials
* rules.yaml - Contains all rules which will be applied when filtering attributes from MISP
* map.yaml - File which maps MISP fields to your custom active list structure
* priorities.yaml - MISP organisations priorities

### Configuration
You can instruct MISP2ArcSight in two ways - by providing command line parameters or by putting values into config file. Parameters overrides config file.<br/>
You can write config file in yaml or json format.<br/>

In the configs directory there are example files. You can simply copy each and remove ".example" part of the filename.<br/>
Than adjust the each file to your needs.

### Run
Help:
```bash
python3 main_connection.py -h
```

Extract attributes since 1 hour from MISP and display what changes would it generate to active lists:
```bash
python3 main_connection.py --timestamp 1h
```

Export all attributes from MISP:
```bash
python3 main_connection.py --timestamp 0 --export > base.json
```

Take attributes from file and apply it to active lists:
```bash
python3 main_connection.py --input base.json --production
```

## Data process flow
There are two basic states in whole process: exist in ArcSight and doesn't exist in ArcSight.

Data is processed in the following order in production mode:
* Download attributes from MISP
* Apply proposals to attributes - It merges attributes with proposals according to priorities file
* Filter attributes - according to rules file
* Combine identical attributes
* Skip unpublished if selected
* Add entries to ArcSight
* Delete entries from ArcSight
* Verify changes and print the result

If you didn't run with `--production` adding and deleting entries will not be conducted. Instead json files will be generated with current and expected state of ArcSight active lists. Additionally you will be prompted to stdout human readable info about intended changes to active lists.


Piped attributes are split into two identical attributes with different type and value. For example domain|ip: google.com|8.8.8.8 is split into two attributes:
* domain: google.com
* ip: 8.8.8.8

## License
[GNU General Public License v3.0](https://github.com/dawid-czarnecki/COPYING)