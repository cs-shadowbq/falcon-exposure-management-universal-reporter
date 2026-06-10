"""falcon-application-inventory-cli — CrowdStrike Falcon Exposure Management Universal Reporter CLI tool.

Concurrently downloads application inventory, vulnerability, and configuration
assessment data from CrowdStrike Falcon and writes it to one or more output
formats (JSON, JSONL, XML).

Install::

    pip install falcon-application-inventory-cli

Run::

    femur --env-file talon1.env --output inventory.json
"""
