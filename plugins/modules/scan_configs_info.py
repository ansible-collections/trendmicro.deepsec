#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Adam Miller (admiller@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}
DOCUMENTATION = """
---
module: scan_configs_info
short_description: Obtain information about AntiMalware Scan Configs in TrendMicro Deep Security
description:
  - Obtain information about AntiMalware Scan Configs in TrendMicro Deep Security
version_added: "2.9"
options:
  id:
    description:
      - FIXME FIXME FIXME
    required: false
    type: str

author: Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>"
"""


# FIXME - provide correct example here
RETURN = """
    "scan_configs": [
        {
            "alert": true,
            "antiMalwareId": 1,
            "configurationType": 1,
            "correlativeScan": false,
            "description": "",
            "documentRecovery": false,
            "enableBehaviorMonitoringDetection": false,
            "excludedScanProcessFileListID": 1,
            "filesToScan": 1,
            "foldersToScan": 1,
            "heuristicDetectionEnabled": true,
            "heuristicDetectionOption": 0,
            "intelliTrapEnabled": true,
            "maximumScanLayers": 2,
            "name": "Default Real-Time Scan Configuration",
            "realtimeMemoryScan": false,
            "remediationActionsOption": 0,
            "scanAction": 1,
            "scanActionForCVE": 3,
            "scanActionForHeuristicDetection": 1,
            "scanActionForOtherThreats": 4,
            "scanActionForPacker": 3,
            "scanActionForSpyware": 3,
            "scanActionForTrendX": 3,
            "scanActionForTrojans": 3,
            "scanActionForVirus": 4,
            "scanCompressed": true,
            "scanCompressedNumberOfFiles": 10,
            "scanCompressedSmaller": 2,
            "scanCustomActionForGeneric": 0,
            "scanFilesActivity": 3,
            "scanNetworkFolder": false,
            "scanOLE": true,
            "scanOLEExploit": true,
            "scanOLELayer": 3,
            "spywareEnabled": true,
            "trendxScanEnabled": false,
            "unScannableFileAction": 1
        }
    ]
"""

EXAMPLES = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text

from ansible.module_utils.urls import Request
from ansible.module_utils.six.moves.urllib.parse import quote
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible_collections.trendmicro.deepsec.plugins.module_utils.deepsec import (
    DeepSecurityRequest,
)

import copy
import json


def main():

    argspec = dict(id=dict(required=False, type="int"))

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)

    deepsec_request = DeepSecurityRequest(module)

    scan_configs = deepsec_request.get(
        "/rest/policies/antimalware/scanConfigs", query_string_auth=True
    )

    if "antiMalwareScanConfigListing" in scan_configs:
        module.exit_json(
            scan_configs=scan_configs["antiMalwareScanConfigListing"][
                "scanConfigs"
            ],
            changed=False,
        )
    else:
        module.fail_json(msg="Unable to retrieve Scan Config info.")


if __name__ == "__main__":
    main()
