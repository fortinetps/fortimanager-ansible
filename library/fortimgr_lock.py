#!/usr/bin/python
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community"
}

DOCUMENTATION = '''
---
module: fortimgr_lock
version_added: "2.3"
short_description: Manages ADOM locking and unlocking
description:
  - Manages FortiManager ADOM locking and unlocking using jsonrpc API
author: Jacob McGill (@jmcgill298), Don Yao (@fortinetps)
options:
  host:
    description:
      - The FortiManager's Address.
    required: true
    type: str
  port:
    description:
      - The TCP port used to connect to the FortiManager if other than the default used by the transport
        method(http=80, https=443).
    required: false
    type: int
  use_ssl:
    description:
      - Determines whether to use HTTPS(True) or HTTP(False).
    required: false
    default: True
    type: bool
  validate_certs:
    description:
      - Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False).
    required: false
    default: False
    type: bool
  session_id:
    description:
      - The session_id of an established and active session
    required: false
    type: str
  username:
    description:
      - The username used to authenticate with the FortiManager.
    required: false
    type: str
  password:
    description:
      - The password associated with the username account.
    required: false
    type: str
  adom:
    description:
      - The ADOM that should have device being added to or removed from.
    required: false
    default: root
    type: str
  lock:
    description:
      - Locks the ADOM in the FortiManager.
      - True ensures the ADOM is locked.
    required: false
    type: bool
    default: False
  save:
    description:
      - Saves the config before unlocking a session.
      - True saves the configuration.
      - False does not save the configuration and all changes in the session will be lost if unlocked.
    required: false
    default: False
    type: bool
  unlock:
    description:
      - Unlocks the ADOM in the FortiManager.
      - True ensures the ADOM is unlocked and closes the current session with the FortiManager.
    required: false
    type: bool
    default: False
'''

EXAMPLES = '''
- name: Lock the lab ADOM
  fortimgr_lock:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    adom: "lab"
    lock: True
  register: session
- name: Set Session ID
  set_fact:
    session_id: "{{ session.session_id }}"
- name: Make Change
  fortimgr_address:
    host: "{{ inventory_hostname }}"
    session_id: "{{ session_id }}"
    adom: "lab"
    address_name: "Server01"
    type: "ipmask"
    subnet: "10.1.1.1/32"
- name: Save and Unlock the ADOM
  fortimgr_lock:
    host: "{{ inventory_hostname }}"
    session_id: "{{ session_id }}"
    adom: "lab"
    save: True
    unlock: True
'''

RETURN = '''
locked:
    description: States whether the ADOM was successfully locked during module execution. This does not report the
                 current lock status.
    returned: always
    type: bool
    sample: True
saved:
    description: States whether the ADOM was successfully saved during module execution.
    returned: always
    type: bool
    sample: True
unlocked:
    description: States whether the ADOM was successfully unlocked during module execution. This does not report the
                 current lock status.
    returned: always
    type: bool
    sample: False
session_id:
    description: The session ID created by the FortiManager upon login.
    returned: when locked is True
    type: str
    sample: "By6M1iHhyGnFY9cLRdRaaaXCgelNkjEKIlS7fQEilwH0XmH99nsaepk9EE3pWvySssspRzMCmr/ltYavQnuIjA=="
'''

from ansible.module_utils.fortimgr_utils import *


def main():
    argument_spec = dict(
        adom=dict(required=False, type="str"),
        host=dict(required=False, type="str"),
        port=dict(required=False, type="int"),
        username=dict(fallback=(env_fallback, ["ANSIBLE_NET_USERNAME"])),
        password=dict(fallback=(env_fallback, ["ANSIBLE_NET_PASSWORD"]), no_log=True),
        use_ssl=dict(required=False, type="bool"),
        validate_certs=dict(required=False, type="bool"),
        provider=dict(required=False, type="dict"),
        save=dict(required=False, type="bool"),
        session_id=dict(required=False, type="str"),
        lock=dict(required=False, type="bool"),
        unlock=dict(required=False, type="bool")
    )

    module = AnsibleModule(argument_spec)

    # handle params and insure they are represented as the data type expected by fortimanager
    host = module.params["host"]
    port = module.params["port"]
    use_ssl = module.params["use_ssl"]
    if use_ssl is None:
        use_ssl = True
    validate_certs = module.params["validate_certs"]
    if validate_certs is None:
        validate_certs = False
    session_id = module.params["session_id"]
    username = module.params["username"]
    password = module.params["password"]
    adom = module.params["adom"]
    lock = module.params["lock"]
    save = module.params["save"]
    unlock = module.params["unlock"]

    argument_check = dict(adom=adom, host=host)
    for key, val in argument_check.items():
        if not val:
            module.fail_json(msg="{} is required".format(key))

    kwargs = dict()
    if port:
        kwargs["port"] = port

    # use established session id or validate successful login
    session = FortiManager(host, username, password, use_ssl, validate_certs, adom, **kwargs)
    if session_id:
        session.session = session_id
    else:
        session_login = session.login()
        if not session_login.json()["result"][0]["status"]["code"] == 0:
            module.fail_json(msg="Unable to login", fortimgr_response=session_login.json())

    results = {"locked": False, "saved": False, "unlocked": False, "changed": True}
    
    if lock:
        session.config_lock(module)
        results.update(dict(locked=True, session_id=session.session))
    
    if save:
        save_status = session.save()
        if save_status["result"][0]["status"]["code"] != 0:
            module.fail_json(msg="Unable to Save Session Config", session_id=session.session, fortimgr_response=save_status)

        results["saved"] = True
    
    if unlock:
        unlock_status = session.unlock()
        if unlock_status["result"][0]["status"]["code"] != 0:
            module.fail_json(msg="Unable to Unlock Session", session_id=session.session, fortimgr_response=unlock_status)

        results["unlocked"] = True

        # logout, build in check for future logging capabilities
        session_logout = session.logout()
        # if not session_logout.json()["result"][0]["status"]["code"] == 0:
        #     results["msg"] = "Completed tasks, but unable to logout of FortiManager"
        #     module.fail_json(**results)

    return module.exit_json(**results)


if __name__ == "__main__":
    main()