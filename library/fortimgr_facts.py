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
module: fortimgr_facts
version_added: "2.3"
short_description: Gathers facts from the FortiManager
description:
  - Gathers facts from the FortiManager using jsonrpc API
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
      - The ADOM that should have package installed should belong to.
    required: false
    type: str
  adoms:
    description:
      - A list of ADOMs for which configurations from FortiManager will be retrieved; "all" can be used to retrieve all ADOMs.
      - If "all" is used, or the value is a list of ADOM names (as strings), then all packages for each ADOM will be retrieved.
      - Passing a list of dictionaries with "name" and "package" keys can be used to limit the scope of policies retrieved.
        A key/value pair is required for each package (the dictionary values cannot be lists).
      - The objects and policy elements will be collected based on what is listed in the config_filter param.
    required: false
    type: list
  config_filter:
    description:
      - The list of configuration items to retrieve from the list of ADOMs and FortiGates managed by the FortiManager.
      - This list will only be used if the fortigates or adoms parameters are passed.
    required: false
    type: list
    choices: ["all", "route", "address", "address_group", "service", "service_group", "ip_pool", "vip", "vip_group", "policy"]
  fortigate_name:
    description:
      - The name to use as the config dictionary key when returning configuration data.
        This is only used when fortigates is all or a list of fortigate names.
      - C(device_id) will use the device ID that FortiManager has associated to the device.
      - C(hostname) will use the hostname of the device.
    required: false
    choices: [device_id, hostname]
    default: device_id
    type: str
  fortigates:
    description:
      - A list of FortiGates to retrieve device information for; "all" can be used to retrieve all devices managed by
        the FortiManger.
      - If config_filter is defined, this list will be used to determine what devices to retrieve configuration from.
      - If config_filter is defined, this list should be a list of dictionaries with "name" and "vdom" keys defining
        the mapping for fortigate and vdom.
    required: false
    type: list
'''

EXAMPLES = '''
- name: Get Facts
  fortimgr_facts:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    adom: "lab"
- name: Get FortiGates
  fortimgr_facts:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    adom: "lab"
    fortigates:
      - "lab"
      - "prod"
      - "dmz"
- name: Get Fortigate Configs
  fortimgr_facts:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    adom: "lab"
    fortigates:
      - name: "lab"
        vdom: "root"
      - name: "prod"
        vdom: "root"
      - name: "dmz"
        vdom: "web"
      - name: "dmz"
        vdom: "dmz"
    config_filter:
      - "route"
      - "policy"
- name: Get All Fortigate Configs
  fortimgr_facts:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    adom: "lab"
    fortigates: "all"
    config_filter: "all"
- name: Get FortiManager Configs
  fortimgr_facts:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    adoms:
      name: "lab"
      package: "lab"
    config_filter: "all" 
'''

RETURN = '''
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
        adoms=dict( required=False, type="list"),
        config_filter=dict(required=False, type="list"),
        fortigate_name=dict(choices=["device_id", "hostname"], type="str"),
        fortigates=dict(required=False, type="list")
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
    adoms = module.params["adoms"]
    if isinstance(adoms, str):
        adoms = [adoms]
    config_filter = module.params["config_filter"]
    if isinstance(config_filter, str):
        config_filter = [config_filter]
    fortigate_name = module.params["fortigate_name"]
    if fortigate_name is None:
        fortigate_name = "device_id"
    fortigates = module.params["fortigates"]
    if isinstance(fortigates, str):
        fortigates = [fortigates]


    # validate required arguments are passed; not used in argument_spec to allow params to be called from provider
    argument_check = dict(host=host)
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

    # collect and normalize fortimanager high availability info
    fm_ha_status = session.get_ha()
    fm_ha = dict(cluster_id=fm_ha_status.get("clusterid"), heartbeat_int=fm_ha_status.get("hb-interval"),
                 hearbeat_threshold=fm_ha_status.get("hb-lost-threshold"), mode=fm_ha_status.get("mode"))

    # collect and normalize fortimanager adom info
    fm_adoms = session.get_adoms_fields(["desc", "flags", "mode", "name", "os_ver"])
    adom_list = []
    for adom in fm_adoms:
        if isinstance(adom.get("flags"), str):
            # convert single entry flags to match multi-entry flags by putting single in a list
            adom["flags"] = [adom["flags"]]

        adom_list.append(adom)

    # collect fortimanager status, normalize data, and append ha and adom info
    fm_status = session.get_status()
    fortimanager = dict(name=fm_status.get("Hostname"), adom=fm_status.get("Admin Domain Configuration"),
                        high_availabilty=fm_ha, license_status=fm_status.get("License Status"),
                        platform=fm_status.get("Platform Type"), serial_num=fm_status.get("Serial Number"),
                        version=fm_status.get("Version"), adoms=adom_list)

    # collect fortigate information and config if specified
    if fortigates:
        device_fields = ["app_ver", "av_ver", "build", "conf_status", "conn_mode", "conn_status", "db_status", "desc",
                         "dev_status", "ha_group_id", "ha_group_name", "ha_mode", "hostname", "ip", "ips_ver", "flags",
                         "last_checked", "last_resync", "mgmt_if", "mgmt_mode", "mgt_vdom", "os_type", "os_ver",
                         "patch", "platform_str", "sn", "source", "vdom"]

        if "all" in fortigates:
            devices = session.get_devices_fields(device_fields)
        # catch string input that ansible module converts to a list
        elif len(fortigates) == 1 and isinstance(fortigates[0], str):
            devices = session.get_device_fields(fortigates[0], device_fields)
        # capture data for list of devices
        elif isinstance(fortigates[0], str):
            device_filter = ["hostname", "in", ""]
            for device in fortigates:
                # add fortigate and , to all but last device to string
                if device != fortigates[-1]:
                    device_filter[2] += "{}, ".format(device)
                else:
                    device_filter[2] += device
            devices = session.get_devices_fields(device_fields, device_filter)
        # capture data for list of devices as a dict
        elif isinstance(fortigates[0], dict):
            device_filter = ["hostname", "in", ""]
            for device in fortigates:
                # add fortigate and , to all but last device to string
                if device["name"] != fortigates[-1]["name"]:
                    device_filter[2] += "{}, ".format(device["name"])
                else:
                    device_filter[2] += device["name"]
            devices = session.get_devices_fields(device_fields, device_filter)
    else:
        devices = []

    configs = {}

    # build list of all devices and vdom mappings if all or fortigate names are used for devices
    if fortigates and isinstance(fortigates[0], str) and config_filter:
        for device in devices:
            for vdom in device["vdom"]:
                if fortigate_name == "hostname":
                    fortigate_key = device.get("hostname")
                else:
                    fortigate_key = vdom.get("devid")

                if fortigate_key not in configs:
                    configs[fortigate_key] = {}

                if "all" in config_filter:
                    # iterate through each fortigate and append a dictionary of configuration items
                    config_dict = {"static_routes": session.get_device_config(vdom["devid"], vdom["name"], "router/static"),
                                   "addresses": session.get_device_config(vdom["devid"], vdom["name"], "firewall/address"),
                                   "address_groups": session.get_device_config(vdom["devid"], vdom["name"], "firewall/addrgrp"),
                                   "services": session.get_device_config(vdom["devid"], vdom["name"], "firewall/service/custom"),
                                   "service_groups": session.get_device_config(vdom["devid"], vdom["name"], "firewall/service/group"),
                                   "ip_pools": session.get_device_config(vdom["devid"], vdom["name"], "firewall/ippool"),
                                   "vips": session.get_device_config(vdom["devid"], vdom["name"], "firewall/vip"),
                                   "vip_groups": session.get_device_config(vdom["devid"], vdom["name"], "firewall/vipgrp"),
                                   "policies": session.get_device_config(vdom["devid"], vdom["name"], "firewall/policy")}

                    configs[fortigate_key].update({vdom["name"]: config_dict})
                else:
                    config_dict = {}
                    if "route" in config_filter:
                        config_dict["static_routes"] = session.get_device_config(vdom["devid"], vdom["name"], "router/static")
        
                    if "address" in config_filter:
                        config_dict["addresses"] = session.get_device_config(vdom["devid"], vdom["name"], "firewall/address")
        
                    if "address_group" in config_filter:
                        config_dict["address_groups"] = session.get_device_config(vdom["devid"], vdom["name"], "firewall/addrgrp")
        
                    if "service" in config_filter:
                        config_dict["services"] = session.get_device_config(vdom["devid"], vdom["name"], "firewall/service/custom")
        
                    if "service_group" in config_filter:
                        config_dict["service_groups"] = session.get_device_config(vdom["devid"], vdom["name"], "firewall/service/group")
        
                    if "ip_pool" in config_filter:
                        config_dict["ip_pools"] = session.get_device_config(vdom["devid"], vdom["name"], "firewall/ippool")
        
                    if "vip" in config_filter:
                        config_dict["vips"] = session.get_device_config(vdom["devid"], vdom["name"], "firewall/vip")
        
                    if "vip_group" in config_filter:
                        config_dict["vip_groups"] = session.get_device_config(vdom["devid"], vdom["name"], "firewall/vipgrp")
        
                    if "policy" in config_filter:
                        config_dict["policies"] = session.get_device_config(vdom["devid"], vdom["name"], "firewall/policy")
    
                    configs[fortigate_key].update({vdom["name"]: config_dict})
    
    # build list of all devices and vdom mappings if fortigate name and vdom dicts are used for devices
    elif fortigates and isinstance(fortigates[0], dict) and config_filter:
        for device in fortigates:
            fg_name = device["name"]
            vdom_name = device["vdom"]
            if fg_name not in configs:
                configs[fg_name] = {}

            if "all" in config_filter:
                # iterate through each fortigate and append a dictionary of configuration items
                config_dict = {"static_routes": session.get_device_config(fg_name, vdom_name, "router/static"),
                               "addresses": session.get_device_config(fg_name, vdom_name, "firewall/address"),
                               "address_groups": session.get_device_config(fg_name, vdom_name, "firewall/addrgrp"),
                               "services": session.get_device_config(fg_name, vdom_name, "firewall/service/custom"),
                               "service_groups": session.get_device_config(fg_name, vdom_name, "firewall/service/group"),
                               "ip_pools": session.get_device_config(fg_name, vdom_name, "firewall/ippool"),
                               "vips": session.get_device_config(fg_name, vdom_name, "firewall/vip"),
                               "vip_groups": session.get_device_config(fg_name, vdom_name, "firewall/vipgrp"),
                               "policies": session.get_device_config(fg_name, vdom_name, "firewall/policy")}

                configs[fg_name].update({vdom_name: config_dict})
            else:
                config_dict = {}
                if "route" in config_filter:
                    config_dict["static_routes"] = session.get_device_config(fg_name, vdom_name, "router/static")
        
                if "address" in config_filter:
                    config_dict["addresses"] = session.get_device_config(fg_name, vdom_name, "firewall/address")
        
                if "address_group" in config_filter:
                    config_dict["address_groups"] = session.get_device_config(fg_name, vdom_name, "firewall/addrgrp")
        
                if "service" in config_filter:
                    config_dict["services"] = session.get_device_config(fg_name, vdom_name, "firewall/service/custom")
        
                if "service_group" in config_filter:
                    config_dict["service_groups"] = session.get_device_config(fg_name, vdom_name, "firewall/service/group")
        
                if "ip_pool" in config_filter:
                    config_dict["ip_pools"] = session.get_device_config(fg_name, vdom_name, "firewall/ippool")
        
                if "vip" in config_filter:
                    config_dict["vips"] = session.get_device_config(fg_name, vdom_name, "firewall/vip")
        
                if "vip_group" in config_filter:
                    config_dict["vip_groups"] = session.get_device_config(fg_name, vdom_name, "firewall/vipgrp")
        
                if "policy" in config_filter:
                    config_dict["policies"] = session.get_device_config(fg_name, vdom_name, "firewall/policy")
    
                configs[fg_name].update({vdom_name: config_dict})

    fortimgr_configs = {}

    if adoms and config_filter:
        # build list of dicts if all adoms if all is used for devices
        if "all" in adoms:
            adom_dicts = []
            # adom_list is generated in the fortimanager device facts section
            for adom in adom_list:
                if adom.get("name"):
                    adom_name = adom["name"]
                    packages = session.get_all_packages(adom_name)
                    for package in packages:
                        adom_dicts.append({"name": adom_name, "package": package})

        # build list of dicts if adoms is a list of strings
        elif isinstance(adoms[0], str):
            adom_dicts = []
            for adom in adoms:
                packages = session.get_all_packages(adom)
                for package in packages:
                    adom_dicts.append({"name": adom, "package": package})
        
        # normalize adom list to use adom_dicts variable name
        elif isinstance(adoms[0], dict):
            adom_dicts = adoms
        
        else:
            adom_dicts = []

        for package in adom_dicts:
            adom_name = package["name"]
            pkg_name = package["package"]
            # create adom key and config dictionary on first policy package collection or object collection
            if adom_name not in fortimgr_configs:
                if "all" in config_filter:
                    fortimgr_configs[adom_name] = {
                        "addresses": session.get_all_custom("pm/config/adom/{}/obj/firewall/address".format(adom_name)),
                        "address_groups": session.get_all_custom("pm/config/adom/{}/obj/firewall/addrgrp".format(adom_name)),
                        "services": session.get_all_custom("pm/config/adom/{}/obj/firewall/service/custom".format(adom_name)),
                        "service_groups": session.get_all_custom("pm/config/adom/{}/obj/firewall/service/group".format(adom_name)),
                        "ip_pools": session.get_all_custom("pm/config/adom/{}/obj/firewall/ippool".format(adom_name)),
                        "vips": session.get_all_custom("pm/config/adom/{}/obj/firewall/vip".format(adom_name)),
                        "vip_groups": session.get_all_custom("pm/config/adom/{}/obj/firewall/vipgrp".format(adom_name)),
                        pkg_name: {"policies": session.get_all_custom("pm/config/adom/{}/pkg/{}/firewall/policy".format(adom_name, pkg_name))}
                    }
                else:
                    config_dict = {}
                    if "address" in config_filter:
                        config_dict["addresses"] = session.get_all_custom("pm/config/adom/{}/obj/firewall/address".format(adom_name))
            
                    if "address_group" in config_filter:
                        config_dict["address_groups"] = session.get_all_custom("pm/config/adom/{}/obj/firewall/addrgrp".format(adom_name))
            
                    if "service" in config_filter:
                        config_dict["services"] = session.get_all_custom("pm/config/adom/{}/obj/firewall/service/custom".format(adom_name))
            
                    if "service_group" in config_filter:
                        config_dict["service_groups"] = session.get_all_custom("pm/config/adom/{}/obj/firewall/service/group".format(adom_name))
            
                    if "ip_pool" in config_filter:
                        config_dict["ip_pools"] = session.get_all_custom("pm/config/adom/{}/obj/firewall/ippool".format(adom_name))
            
                    if "vip" in config_filter:
                        config_dict["vips"] = session.get_all_custom("pm/config/adom/{}/obj/firewall/vip".format(adom_name))
            
                    if "vip_group" in config_filter:
                        config_dict["vip_groups"] = session.get_all_custom("pm/config/adom/{}/obj/firewall/vipgrp".format(adom_name))
            
                    if "policy" in config_filter:
                        config_dict[pkg_name] = {"policies": session.get_all_custom("pm/config/adom/{}/pkg/{}/firewall/policy".format(adom_name, pkg_name))}

                    fortimgr_configs[adom_name] = config_dict
            # only add new package key and policy configuration if policies need to be collected; objects are per adom so no need to collect after first pass
            elif "all" in config_filter or "policy" in config_filter:
                fortimgr_configs[adom_name][pkg_name] = {"policies": session.get_all_custom("pm/config/adom/{}/pkg/{}/firewall/policy".format(adom_name, pkg_name))}

    results = dict(fortimanager=fortimanager, devices=devices, configs=configs, fortimgr_configs=fortimgr_configs)

    # logout, build in check for future logging capabilities
    if not session_id:
        session_logout = session.logout()
        # if not session_logout.json()["result"][0]["status"]["code"] == 0:
        #     results["msg"] = "Completed tasks, but unable to logout of FortiManager"
        #     module.fail_json(**results)

    return module.exit_json(ansible_facts=results)


if __name__ == "__main__":
    main()
