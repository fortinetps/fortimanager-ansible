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
module: fortimgr_install
version_added: "2.3"
short_description: Manages ADOM package/device installs
description:
  - Manages FortiManager package/device installs using jsonrpc API
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
      - The ADOM that should have package/device installed should belong to.
    required: true
    type: str
  lock:
    description:
      - True locks the ADOM, makes necessary configuration updates, saves the config, and unlocks the ADOM
    required: false
    default: True
    type: bool
  state:
    description:
      - The desired state of the package.
      - Present will update the configuration if needed.
      - Preview (or check mode) will return a preview of what will be pushed to the end device.
      - Assign will add device to the installation targets of policy package
      - Unassign will remove device from the installation targets of policy package
    required: false
    default: present
    type: str
    choices: ["present", "preview", "assign", "unassign"]
  adom_revision_comments:
    description:
      - Comments to add to the ADOM revision if creating a revision.
    required: false
    type: str
  adom_revision_name:
    description:
      - The name to give the ADOM revision if creating a revision.
    required: false
    type: str
  check_install:
    description:
      - Determines if the install will only be committed if the FortiGate is in sync and connected with the FortManager.
      - True performs the check.
      - False attempts the install regardless of device status.
    required: false
    type: bool
  dst_file:
    description:
      - The file path/name where to write the install preview to.
    required: false
    type: str
  fortigate_name:
    description:
      - The name of FortiGate in consideration for package/device install.
    required: True
    type: str
  fortigate_revision_comments:
    description:
      - Comments to add to the FortiGate revision.
    required: false
    type: str
  install_flags:
    description:
      - Flags to send to the FortiManager identifying how the install should be done.
    required: false
    type: list
    choices: ["cp_all_objs", "generate_rev", "copy_assigned_pkg", "unassign", "ifpolicy_only", "no_ifpolicy",
             "objs_only", "copy_only"]
  package:
    description:
      - The policy package that should be pushed to the end devices.
      - If the package is not specified, then it will install device configuration only
    required: False
    type: strg
  vdom:
    description:
      - The VDOM associated with the FortiGate and package.
    required: false
    type: str
'''

EXAMPLES = '''
- name: FortiManager to assign policy package {{ FMG_POLICY_PACKAGE }} to FortiGate {{ FGT_HA_GROUPNAME }}
fortimgr_install:
    host: "{{ FMG1_IP_ADDRESS }}"
    session_id: "{{ session_id }}"
    adom: "{{ FMG_ADOM }}"
    fortigate_name: "{{ FGT_HA_GROUPNAME }}"
    package: "{{ FMG_POLICY_PACKAGE }}"
    state: "assign"
- name: FortiManager to install policy package {{ FMG_POLICY_PACKAGE }} to FortiGate {{ FGT_HA_GROUPNAME }}
fortimgr_install:
    host: "{{ FMG1_IP_ADDRESS }}"
    session_id: "{{ session_id }}"
    adom: "{{ FMG_ADOM }}"
    fortigate_name: "{{ FGT_HA_GROUPNAME }}"
    package: "{{ FMG_POLICY_PACKAGE }}"
- name: FortiManager to install device config to FortiGate {{ FGT_HA_GROUPNAME }}
fortimgr_install:
    host: "{{ FMG1_IP_ADDRESS }}"
    session_id: "{{ session_id }}"
    adom: "{{ FMG_ADOM }}"
    fortigate_name: "{{ FGT_HA_GROUPNAME }}"
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
        adom=dict(required=True, type="str"),
        state=dict(choices=["present", "preview", "assign", "unassign"], type="str"),
        lock=dict(required=False, type="bool"),
        adom_revision_comments=dict(required=False, type="str"),
        adom_revision_name=dict(required=False, type="str"),
        check_install=dict(required=False, type="bool"),
        dst_file=dict(required=False, type="str"),
        fortigate_name=dict(required=True, type="str"),
        fortigate_revision_comments=dict(required=False, type="str"),
        install_flags=dict(required=False, type="list"),
        package=dict(required=False, type="str"),
        vdom=dict(required=False, type="str")
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
    lock = module.params["lock"]
    if lock is None:
        # lock = True
        lock = False  # to disable default auto_lock_ws to solve Ansible free strategy running issue
    check_install = module.params["check_install"]
    dst = module.params["dst_file"]
    fortigate = module.params["fortigate_name"]

    package = module.params["package"]
    install_flags = module.params["install_flags"]
    if install_flags is None:
        install_flags = []
    vdom = module.params["vdom"]
    if vdom is None:
        vdom = "root"

    # validate required arguments are passed
    argument_check = dict(adom=adom, fortigate_name=fortigate, host=host)
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

    # Add FortiGate to Policy Package Installation Targets
    if state == "assign": # Assign Installation Targets
        # check before we add
        response = session.get_package_installation_targets(adom=adom, package=package)
        if response["result"][0]["status"]["code"] == 0:
            existing_scope_member = response["result"][0]["data"].get("scope member")
            if existing_scope_member is not None:
                for item in existing_scope_member:
                    if item["name"] == fortigate: # return and no changes if FortiGate is already in the targets list
                        module.exit_json(msg="FortiGate is already in this policy package's installation targets list, no changes", changed=False, status=response)
        else:
            module.fail_json(msg="Failed to get Installation Targets information within adom:%s and package:%s." % (adom, package), status=response)

        # FortiGate need to be added to the Installation Targets
        args = dict(
            name=fortigate,
            vdom="root"
        )

        # "if isinstance(v, bool) or v" should be used if a bool variable is added to args
        proposed = dict((k, v) for k, v in args.items() if v)

        assign = session.add_package_installation_targets(adom=adom, package=package, proposed=proposed)
        if assign["result"][0]["status"]["code"] == 0:
            results = dict(assign=assign, changed=True)
        else:
            module.fail_json(**dict(status=assign, msg="Add installation target was NOT Sucessful; Please Check FortiManager Logs"))

    # Remove FortiGate from Policy Package Installation Targets
    elif state == "unassign": # Unassign Installation Targets
        # check before we del
        target_exist = False
        response = session.get_package_installation_targets(adom=adom, package=package)
        if response["result"][0]["status"]["code"] == 0:
            existing_scope_member = response["result"][0]["data"]["scope member"]
            for item in existing_scope_member:
                if item["name"] == fortigate: # we found the target we are going to delete
                    target_exist = True
        else:
            module.fail_json(msg="Failed to get Installation Targets information within adom:%s and package:%s." % (adom, package), status=response)

        if target_exist == False:
            module.exit_json(msg="FortiGate isn't in this policy package's installation targets list, can't be removed, no changes", changed=False, status=response)

        args = dict(
            name=fortigate,
            vdom="root"
        )

        # "if isinstance(v, bool) or v" should be used if a bool variable is added to args
        proposed = dict((k, v) for k, v in args.items() if v)

        assign = session.delete_package_installation_targets(adom=adom, package=package, proposed=proposed)
        if assign["result"][0]["status"]["code"] == 0:
            results = dict(assign=assign, changed=True)
        else:
            module.fail_json(**dict(status=assign, msg="Remove installation target was NOT Sucessful; Please Check FortiManager Logs"))

    # generate install preview if specified or module ran in check mode
    elif state == "preview" or module.check_mode:
        install = session.preview_install(package, fortigate, [vdom], lock)
        if install["result"][0]["status"]["code"] == 0 and "message" in install["result"][0]["data"]:
            # write preview to file if destination file specified
            if dst:
                with open(dst, "w") as preview:
                    preview.write("\n{}\n\n".format(time.asctime().upper()))
                    for line in install["result"][0]["data"]["message"]:
                        preview.write(line)
            results = dict(changed=True, install=install)
        else:
            # fail if install preview had issues
            if install["id"] == 1:
                install["fail_state"] = "install_preview"
                results = dict(status=install, msg="Module Failed Issuing Install with Preview Flag")
                module.fail_json(**results)
            # fail if generating the preview had issues
            elif install["id"] == 2:
                install["fail_state"] = "generate_preview"
                results = dict(status=install, msg="Module Failed Generating a Preview")
                module.fail_json(**results)
            # fail if cancelling the install had issues
            elif install["id"] == 3:
                install["fail_state"] = "cancel_install"
                results = dict(status=install, msg="Module Failed Cancelling the Install Task")
                module.fail_json(**results)
            # fail if retrieving the preview results had issues
            elif install["id"] == 4:
                install["fail_state"] = "retrieving_preview"
                results = dict(status=install, msg="Module Failed Retrieving the Preview Message")
                module.fail_json(**results)
    else:
        # verify fortigate health if check_install is True
        if check_install:
            status = session.get_install_status(fortigate)["result"][0]
            if status["data"] is None:
                module.fail_json(msg="Unable to find {} in ADOM {}".format(fortigate, adom))
            elif status["status"]["code"] != 0 or status["data"][0]["conf_status"] not in ["insync", "synchronized"] or status["data"][0]["conn_status"] != "up":
                results = dict(status=status, msg="Device Status did not Pass Checks")
                module.fail_json(**results)

        if package: # if package is specified, do policy install
            # check before install, if the specified package has been installed, then skip the installation
            response = session.get_device_package_status(adom, fortigate, vdom)
            # module.fail_json(msg="test", status=response)
            if response["result"][0]["status"]["code"] == 0:
                if response["result"][0]["data"]["status"] == "installed" and response["result"][0]["data"]["pkg"] == package:
                    module.exit_json(msg="Package %s is already installed on FortiGate %s" % (package, fortigate), status=response)

            args = dict(
                adom=adom,
                adom_rev_comments=module.params["adom_revision_comments"],
                adom_rev_name=module.params["adom_revision_name"],
                dev_rev_comments=module.params["fortigate_revision_comments"],
                pkg=package,
                scope=[{"name": fortigate, "vdom": "global"}, {"name": fortigate, "vdom": "root"}]
            )

            # "if isinstance(v, bool) or v" should be used if a bool variable is added to args
            proposed = dict((k, v) for k, v in args.items() if v)

            # let install handle locking and unlocking if lock is True
            if lock:
                proposed["flags"] = install_flags
                proposed["flags"].append("auto_lock_ws")

            install = session.install_package(proposed)
            if install["result"][0]["status"]["code"] == 0 and install["result"][0]["data"]["state"] == "done":
                results = dict(install=install, changed=True)
            else:
                module.fail_json(**dict(status=install, msg="Install policy was NOT Sucessful; Please Check FortiManager Logs"))

        else:   # if package is not specified, do device/config only install
            # check before install, if the config status is synced, skip the installation
            response = session.get_device_fields(device=fortigate, fields=[])
            if len(response): # which should be one and only device
                # if there is no changes on FortiManager Device Database or no changes on FortiGate local Device Config, skip the install
                if response[0]["db_status"] == "nomod" and response[0]["conf_status"] != "outofsync":
                    module.exit_json(msg="FortiManager Device Database and FortiGate Device Config are synced", status=response)
                    
            args = dict(
                adom=adom,
                adom_rev_comments=module.params["adom_revision_comments"],
                adom_rev_name=module.params["adom_revision_name"],
                dev_rev_comments=module.params["fortigate_revision_comments"],
                scope=[{"name": fortigate, "vdom": "global"}, {"name": fortigate, "vdom": "root"}]
            )

            # "if isinstance(v, bool) or v" should be used if a bool variable is added to args
            proposed = dict((k, v) for k, v in args.items() if v)

            # let install handle locking and unlocking if lock is True
            if lock:
                proposed["flags"] = install_flags
                proposed["flags"].append("auto_lock_ws")

            install = session.install_device(proposed)
            if install["result"][0]["status"]["code"] == 0 and install["result"][0]["data"]["state"] == "done":
                results = dict(install=install, changed=True)
            else:
                module.fail_json(**dict(status=install, msg="Install Device Config was NOT Sucessful; Please Check FortiManager Logs"))

    # logout, build in check for future logging capabilities
    if not session_id:
        session_logout = session.logout()
        # if not session_logout.json()["result"][0]["status"]["code"] == 0:
        #     results["msg"] = "Completed tasks, but unable to logout of FortiManager"
        #     module.fail_json(**results)

    return module.exit_json(**results)


if __name__ == "__main__":
    main()
