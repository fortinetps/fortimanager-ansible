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
    "metadata_version": "1.0",
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
  state:
    description:
      - The desired state of the dynamic interface or dynamic interface mapping.
      - Present will add dynamic interface or dynamic interface mapping to FortiManager ADOM.
      - Absent will delete dynamic interface from FortiManager ADOM.
    required: false
    default: present
    type: str
    choices: ["present", "absent"]
  name:
    description:
      - The dynamic interface name.
    required: true
    type: str
  fortigate:
    description:
      - The FortiGate device name, required when doing dynamic interface mapping.
    required: false
    type: str
  interface:
    description:
      - The FortiGate interface name, required when doing dynamic interface mapping.
    required: false
    type: str
'''

EXAMPLES = '''
- name: FortiManager create dynamic interface
fortimgr_dynamic_interface:
    host: "{{ FMG1_IP_ADDRESS }}"
    session_id: "{{ session_id }}"
    adom: "{{ FMG_ADOM }}"
    name: "{{ FGT_INSIDE_ALIAS }}"
- name: FortiManager set dynamic interface mapping
fortimgr_dynamic_interface:
    host: "{{ FMG1_IP_ADDRESS }}"
    session_id: "{{ session_id }}"
    adom: "{{ FMG_ADOM }}"
    name: "{{ FGT_OUTSIDE_ALIAS }}"
    fortigate: "{{ FGT_HA_GROUPNAME }}"
    interface: "{{ FGT_OUTSIDE_INTERFACE }}"
- name: FortiManager delete dynamic interface
fortimgr_dynamic_interface:
    host: "{{ FMG1_IP_ADDRESS }}"
    session_id: "{{ session_id }}"
    adom: "{{ FMG_ADOM }}"
    name: "{{ FGT_OUTSIDE_ALIAS }}"
    state: "absent"
'''

RETURN = '''
'''

from ansible.module_utils.fortimgr_utils import *


def main():
    argument_spec = dict(
        host=dict(required=True, type="str"),
        port=dict(required=False, type="int"),
        use_ssl=dict(required=False, type="bool"),
        validate_certs=dict(required=False, type="bool"),
        session_id=dict(required=False, type="str"),
        username=dict(fallback=(env_fallback, ["ANSIBLE_NET_USERNAME"])),
        password=dict(fallback=(env_fallback, ["ANSIBLE_NET_PASSWORD"]), no_log=True),
        adom=dict(required=False, type="str"),
        state=dict(choices=["present", "absent"], type="str"),
        name=dict(required=True, type="str"),
        fortigate=dict(required=False, type="str"),
        interface=dict(required=False, type="str"),
        vdom=dict(required=False, type="str")
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
    if adom is None:
        adom = "root"
    state = module.params["state"]
    if state is None:
        state = "present"
    name = module.params["name"]
    fortigate = module.params["fortigate"]
    interface = module.params["interface"]
    vdom = module.params["vdom"]
    if vdom is None:
        vdom = "root"

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

    response = session.get_dynamic_interface(adom=adom, interface=name)
    # if state == "present", make sure dynamic interface interface exists on FortiManager
    if state == "present":
        # check if the dynamic interface exists
        # if fortigate is not specified, that mean we only care about the dynamic interface object on FortiManager, no mapping is needed
        if fortigate is None:
            # if dynamic interface is alreay exist
            if response["result"][0]["status"]["code"] == 0:
                module.exit_json(msg="Dynamic interface {} in adom {} already exists, no changes".format(name, adom), changed=False, result=response)
            # else we need to create the new dynamic interface
            else:
                # dynamic interface info
                proposed = {"name": name, "single-intf": False}
                response = session.add_dynamic_interface(adom, name, proposed)
                if response["result"][0]["status"]["code"] == 0:
                    module.exit_json(msg="Added dynamic interface {} in adom {} succeed".format(name, adom), changed=True, result=response)
                else:
                    module.fail_json(msg="Added dynamic interface {} in adom {} failed".format(name, adom), result=response)
        # else if fortigate is specified, that mean we want to get the real mapping created, also we need to create dynamic interface if it is not there
        else:
            dynamic_mapping = None
            add_dynamic_interface = False
            update_existing_mapping = False
            # if dynamic interface is already exist
            # check if the mapping is also exist
            if response["result"][0]["status"]["code"] == 0:
                dynamic_mapping = response["result"][0]["data"].get("dynamic_mapping")
                if dynamic_mapping is not None:
                    for mapping in dynamic_mapping:
                        if mapping["_scope"][0]["name"] == fortigate and mapping["local-intf"][0] == interface:
                            module.exit_json(msg="Dynamic interface {} in adom {} with FortiGate {} and interface {} mapping is already exist, no changes".format(name, adom, fortigate, interface), changed=False, result=response)
                        elif mapping["_scope"][0]["name"] == fortigate and mapping["local-intf"][0] != interface:
                            mapping["local-intf"] = [interface]
                            update_existing_mapping = True
            # else we need to create the new dynamic interface with the new mapping
            else:
                # dynamic interface info
                proposed = {"name": name, "single-intf": False}
                response = session.add_dynamic_interface(adom, name, proposed)
                if response["result"][0]["status"]["code"] != 0:
                    module.fail_json(msg="Added dynamic interface {} in adom {} failed".format(name, adom), result=response)
                else:
                    add_dynamic_interface = True

            args = None
            # or we update the existing dynamic interface with with the updated mapping
            if update_existing_mapping:
                args = {
                    "name": name,
                    "single-intf": False,
                    "dynamic_mapping": dynamic_mapping
                }
            # new dynamic interface and new mapping
            elif add_dynamic_interface:
                args = {
                    "name": name,
                    "single-intf": False,
                    "dynamic_mapping": [{
                        "_scope": [{
                            "name": fortigate,
                            "vdom": "root"
                        }],
                        "local-intf": interface,
                    }]
                }
            # or we append the new mapping to the existing dynamic interface
            else:
                if dynamic_mapping is None:
                    dynamic_mapping = []
                args = {
                    "name": name,
                    "single-intf": False,
                    "dynamic_mapping": dynamic_mapping
                }
                args["dynamic_mapping"].append(
                    {
                        "_scope": [{
                            "name": fortigate,
                            "vdom": "root"
                        }],
                        "local-intf": interface,
                    }
                )

            proposed = dict((k, v) for k, v in args.items() if v)
            response = session.add_dynamic_interface(adom, name, proposed)
            if response["result"][0]["status"]["code"] == 0:
                module.exit_json(msg="Add dynamic interface {} mapping to FortiGate {} {} in adom {} succeed".format(name, fortigate, interface, adom), changed=True, result=response)
            else:
                module.fail_json(msg="Add dynamic interface {} mapping to FortiGate {} {} in adom {} failed".format(name, fortigate, interface, adom), result=response)

    # if state == "absent", we could only remove the dynamic interface object on FortiManager when there is no reference in Firewall Policy
    elif state == "absent":
        # if fortigate is not specified, that mean we only care about the dynamic interface object on FortiManager
        # we are not support this at this time, this would require remove all dependencies
        if response["result"][0]["status"]["code"] != 0:
            module.exit_json(msg="No such dynamic interface {} in adom {}, no changes".format(name, adom), changed=False, result=response)
        elif fortigate is None:
            status, response = session.get_object_where_used(objecturl="adom/{}/obj/dynamic/interface".format(adom), objectid=name)
            if status == 0 and response["result"][0]["data"].get("dynamic_mapping") is None:
                response = session.del_dynamic_interface(adom=adom, interface=name)
                if response["result"][0]["status"]["code"] == 0:
                    module.exit_json(msg="Delete dynamic interface {} in adom {} succeed".format(name, adom), result=response)
                else:
                    module.fail_json(msg="Delete dynamic interface {} in adom {} failed".format(name, adom), changed=False, result=response)
            else:
                if status == 0 and response["result"][0]["data"].get("dynamic_mapping") is not None:
                    module.fail_json(msg="Unable to delete dynamic interface which is still being used", changed=False, result=response)
                else:
                    module.fail_json(msg="Delete dynamic interface {} in adom {} failed".format(name, adom), changed=False, result=response)
        # else if fortigate is specified, that mean we want to remove the mapped interface
        else:
            module.fail_json(msg="Unable to delete dynamic interface from FortiManager, this function is not supported yet")
       

    # logout, build in check for future logging capabilities
    # if not session_id:
    #     session_logout = session.logout()
    # if not session_logout.json()["result"][0]["status"]["code"] == 0:
    #     results["msg"] = "Completed tasks, but unable to logout of FortiManager"
    #     module.fail_json(**results)

    # return module.exit_json(**results)


if __name__ == "__main__":
    main()