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
module: fortimgr_device
version_added: "2.6"
short_description: Add/Delete Managed Device on FortiManager
description:
  - Add/Delete Managed Device on FortiManager using jsonrpc API
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
      - The desired state of the device.
      - Present will add device to FortiManager as managed device.
      - Absent will delete device from FortiManager.
    required: false
    default: present
    type: str
    choices: ["present", "absent"]
  name:
    description:
      - The managed FortiGate device name in FortiManager.
      - This name is unique across all ADOMs in FortiManager.
    required: true
    type: str
'''

EXAMPLES = '''
- name: Add FortiGate to FortiManager in specified adom
fortimgr_device:
    host: "{{ FMG1_IP_ADDRESS }}"
    username: "{{ FMG_USERNAME }}"
    password: "{{ FMG_PASSWORD }}"
    adom: "{{ FMG_ADOM }}"
    fgt: "{{ FGT_HOSTNAME }}"
    name: "{{ FGT_HA_GROUPNAME }}"
register: fmgdev_result
- debug: 
    var: fmgdev_result
- name: Delete FortiGate from FortiManager in specified adom
fortimgr_device:
    host: "{{ FMG1_IP_ADDRESS }}"
    username: "{{ FMG_USERNAME }}"
    password: "{{ FMG_PASSWORD }}"
    adom: "{{ FMG_ADOM }}"
    fgt: "{{ FGT_HOSTNAME }}"
    name: "{{ FGT_HA_GROUPNAME }}"
    state: "absent"
register: fmgdev_result
- debug: 
    var: fmgdev_result
'''

RETURN = '''
install:
    description: The json results from install request.
    returned: Always
    type: dict
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
        fgt=dict(required=True, type="str"),
        sn=dict(required=False, type="str")
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

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
    fgt = module.params["fgt"]
    sn = module.params["sn"]
    
    kwargs = dict()
    if port:
        kwargs["port"] = port

    # validate successful login or use established session id
    session = FortiManager(host, username, password, use_ssl, validate_certs, adom, **kwargs)
    if not session_id:
        session_login = session.login()
        if not session_login.json()["result"][0]["status"]["code"] == 0:
            module.fail_json(msg="Unable to login", fortimgr_response=session_login.json())
    else:
        session.session = session_id

    # before we perform anything on the device, we would like to check if the device is already managed by FortiManager 
    # regardless in which adom, since device name (not hostname) is unique across all adoms in FortiManager
    devices = session.get_device_fields(device=name, fields=[])
    if len(devices):
        ha_group_name = devices[0].get("ha_group_name")
        ha_mode = devices[0].get("ha_mode")
        ha_slave = devices[0].get("ha_slave")
        if ha_slave:
            if state == "present":
                slave_found = None
                update_ha_slave = []
                for slave in ha_slave:
                    new_slave = {}
                    new_slave["name"] = slave["name"]
                    new_slave["role"] = slave["role"]
                    new_slave["sn"] = slave["sn"]
                    update_ha_slave.append(new_slave)
                    if slave["name"] == fgt:
                        slave_found = slave
                if slave_found:
                    module.exit_json(msg="Device with name '%s' from adom '%s' has unit '%s' already, no need to update ha." % (name, session.adom, fgt), changed=False)
                else:
                    new_slave = {}
                    new_slave["name"] = fgt
                    new_slave["role"] = "slave"
                    new_slave["sn"] = sn
                    update_ha_slave.append(new_slave)

                    args = dict(
                        ha_group_name=ha_group_name,
                        ha_mode=ha_mode,
                        ha_slave=update_ha_slave,
                        name=name
                    )

                    proposed = dict((k, v) for k, v in args.items() if v)
                    dev_update = session.update_ha(proposed)
                    if dev_update["result"][0]["status"]["code"] == 0:
                        results = dict(msg="Update/Add Device HA was Successful.", response=dev_update, changed=True, skip=False)
                    else:
                        module.fail_json(msg="Update Device HA was NOT Sucessful; Please Check FortiManager Logs", response=dev_update)
            else: # if state == "absent"
                slave_found = None
                update_ha_slave = []
                for slave in ha_slave:
                    if slave["name"] == fgt:
                        slave_found = slave
                    else:
                        new_slave = {}
                        new_slave["name"] = slave["name"]
                        new_slave["role"] = slave["role"]
                        new_slave["sn"] = slave["sn"]
                        update_ha_slave.append(new_slave)
                if slave_found:
                    if update_ha_slave:
                        args = dict(
                            ha_group_name=ha_group_name,
                            ha_mode=ha_mode,
                            ha_slave=update_ha_slave,
                            name=name
                        )

                        proposed = dict((k, v) for k, v in args.items() if v)
                        dev_update = session.update_ha(proposed)
                        if dev_update["result"][0]["status"]["code"] == 0:
                            results = dict(msg="Update/Del Device HA was Successful.", response=dev_update, changed=True, skip=False)
                        else:
                            module.fail_json(msg="Update Device HA was NOT Sucessful; Please Check FortiManager Logs", response=json.dumps(proposed))

                    else:
                        module.fail_json(msg="Device with name '%s' from adom '%s' has last unit '%s', can't remove last unit from ha." % (name, session.adom, fgt), changed=False)
                else:
                    module.fail_json(msg="Device with name '%s' from adom '%s' has no unit '%s', can't remove it from ha." % (name, session.adom, fgt), changed=False)

                # module.fail_json(msg="2 Update Device HA was NOT Sucessful; Please Check FortiManager Logs")
        else:
            module.fail_json(msg="Device with name '%s' from adom '%s' is not HA cluster, can't update ha." % (name, session.adom))

    else:
        module.fail_json(msg="No such device with name '%s' from adom '%s', can't update ha." % (name, session.adom))

    # logout, build in check for future logging capabilities
    if not session_id:
        session_logout = session.logout()
        # if not session_logout.json()["result"][0]["status"]["code"] == 0:
        #     results["msg"] = "Completed tasks, but unable to logout of FortiManager"
        #     module.fail_json(**results)

    return module.exit_json(**results)
    

if __name__ == "__main__":
    main()

