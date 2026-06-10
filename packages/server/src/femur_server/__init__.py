"""falcon-application-inventory-server — FastAPI REST server.

Serves pre-fetched CrowdStrike Falcon Exposure Management Universal Reporter data over HTTP.
Automatically triggers background re-fetches when data becomes stale.

Install::

    pip install falcon-application-inventory-server

Start::

    femurd --data-dir ./inventory --env-file talon1.env
"""
