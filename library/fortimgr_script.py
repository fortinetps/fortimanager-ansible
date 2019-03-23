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
module: fortimgr_device
version_added: "2.3"
short_description: Manages ADOM package installs
description:
  - Manages FortiManager package installs using jsonrpc API
author: Jacob McGill (@jmcgill298), Don Yao (@fortinetps)
options:
  adom:
    description:
      - The ADOM that should have package installed should belong to.
    required: true
    type: str
  host:
    description:
      - The FortiManager's Address.
    required: true
    type: str
  password:
    description:
      - The password associated with the username account.
    required: false
    type: str
  port:
    description:
      - The TCP port used to connect to the FortiManager if other than the default used by the transport
        method(http=80, https=443).
    required: false
    type: int
  provider:
    description:
      - Dictionary which acts as a collection of arguments used to define the characteristics
        of how to connect to the device.
      - Arguments hostname, username, and password must be specified in either provider or local param.
      - Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.
    required: false
    type: dict
  session_id:
    description:
      - The session_id of an established and active session
    required: false
    type: str
  use_ssl:
    description:
      - Determines whether to use HTTPS(True) or HTTP(False).
    required: false
    default: True
    type: bool
  username:
    description:
      - The username used to authenticate with the FortiManager.
    required: false
    type: str
  validate_certs:
    description:
      - Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False).
    required: false
    default: False
    type: bool
'''

EXAMPLES = '''
  - name: Get Script(s) on FortiManager
    fortimgr_script:
      host: 192.168.99.99
      session_id: "{{ session_id }}"
      adom: root
  - name: Add Script to FortiManager
    fortimgr_script:
      host: 192.168.99.99
      session_id: "{{ session_id }}"
      adom: root
      script_name: test123
      script_content: get system status
  - name: Update Script Content on FortiManager
    fortimgr_script:
      host: 192.168.99.99
      session_id: "{{ session_id }}"
      adom: root
      script_name: test123
      script_content: get system performance status
      script_method: update
  - name: Execute Script on FortiManager
    fortimgr_script:
      host: 192.168.99.99
      session_id: "{{ session_id }}"
      adom: root
      script_name: test123
      script_method: exec
      scope:
        name: "{{ FGT_HA_GROUPNAME }}",
        vdom: "root"        
  - name: Delete Script on FortiManager
    fortimgr_script:
      host: 192.168.99.99
      session_id: "{{ session_id }}"
      adom: root
      script_name: test123
      script_method: delete
'''

RETURN = '''
install:
    description: The json results from install request.
    returned: Always
    type: dict
    sample: 
'''

from ansible.module_utils.fortimgr_utils import *

def main():
    argument_spec = dict(
        adom=dict(required=False, type="str"),
        host=dict(required=False, type="str"),
        password=dict(fallback=(env_fallback, ["ANSIBLE_NET_PASSWORD"]), no_log=True),
        port=dict(required=False, type="int"),
        provider=dict(required=False, type="dict"),
        session_id=dict(required=False, type="str"),
        use_ssl=dict(required=False, type="bool"),
        username=dict(fallback=(env_fallback, ["ANSIBLE_NET_USERNAME"])),
        validate_certs=dict(required=False, type="bool"),
        script_name=dict(required=False, type="str"),
        script_type=dict(choices=["cli", "tcl"], required=False, type="str"),
        script_content=dict(required=False, type="str"),
        script_method=dict(choices=["get", "set", "add", "update", "delete", "exec"], required=False, type="str"),
        script_scope=dict(required=False, type="list")
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
    script_method = module.params["script_method"]
    if script_method is None:
        script_method = "set"
    script_type = module.params["script_type"]
    if script_type is None:
        script_type = "cli"

    # validate required arguments are passed; not used in argument_spec to allow params to be called from provider
    argument_check = dict(adom=adom, host=host)
    for key, val in argument_check.items():
        if not val:
            module.fail_json(msg="{} is required".format(key))

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

    args = dict()
    if script_method in ["set", "add", "update"]:
        args = dict(
            name=module.params["script_name"],
            type=script_type,
            content=module.params["script_content"]
        )
    elif script_method == "exec":
        args = dict(
            adom=module.params["adom"],
            script=module.params["script_name"],
            scope=module.params["script_scope"],
        )

    # "if isinstance(v, bool) or v" should be used if a bool variable is added to args
    proposed = dict((k, v) for k, v in args.items() if v)

    response = session.apply_method_on_script(method=script_method, proposed=proposed)
    if response["result"][0]["status"]["code"] == 0:
        if "data" in response["result"][0]:
            if "state" in response["result"][0]["data"]:
                if response["result"][0]["data"]["state"] == "error":
                    module.fail_json(**dict(status=response, msg="Apply method:" + script_method + " on script:" + module.params["script_name"] + " was NOT Sucessful; Please Check FortiManager Logs"))
        results = dict(response=response, changed=True)
    else:
        module.fail_json(**dict(status=response, msg="Apply method:" + script_method + " on script:" + module.params["script_name"] + " was NOT Sucessful; Please Check FortiManager Logs"))

    # logout, build in check for future logging capabilities
    if not session_id:
        session_logout = session.logout()
        # if not session_logout.json()["result"][0]["status"]["code"] == 0:
        #     results["msg"] = "Completed tasks, but unable to logout of FortiManager"
        #     module.fail_json(**results)

    return module.exit_json(**results)


if __name__ == "__main__":
    main()

