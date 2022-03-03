#!/bin/bash

update-rc.d wazuh-agent defaults 95 10
service wazuh-agent start