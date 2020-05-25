# -*- coding: utf-8 -*-

""" License
    Copyright (C) 2013 YunoHost
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses
"""

""" yunohost_share.py
    Manage share rules
"""
import os
import sys
import yaml
try:
    import miniupnpc
except ImportError:
    sys.stderr.write('Error: Yunohost CLI Require miniupnpc lib\n')
    sys.exit(1)

from moulinette import m18n
from yunohost.utils.error import YunohostError
from moulinette.utils import process
from moulinette.utils.log import getActionLogger
from moulinette.utils.text import prependlines

SHARE_FILE = '/etc/yunohost/share.yml'

logger = getActionLogger('yunohost.share')

def firewall_allow(protocol, port, ipv4_only=False, ipv6_only=False,
                   no_upnp=False, no_reload=False):
    """
    Allow sharing

    Keyword arguments:
        list -- List all Disks
        format -- Format in xfs ext4 btrs

    """
    firewall = firewall_list(raw=True)

    # Validate port
    if not isinstance(port, int) and ':' not in port:
        port = int(port)

    # Validate protocols
    protocols = ['TCP', 'UDP']
    if protocol != 'Both' and protocol in protocols:
        protocols = [protocol, ]

    # Validate IP versions
    ipvs = ['ipv4', 'ipv6']
    if ipv4_only and not ipv6_only:
        ipvs = ['ipv4', ]
    elif ipv6_only and not ipv4_only:
        ipvs = ['ipv6', ]

    for p in protocols:
        # Iterate over IP versions to add port
        for i in ipvs:
            if port not in firewall[i][p]:
                firewall[i][p].append(port)
            else:
                ipv = "IPv%s" % i[3]
                logger.warning(m18n.n('port_already_opened', port=port, ip_version=ipv))
        # Add port forwarding with UPnP
        if not no_upnp and port not in firewall['uPnP'][p]:
            firewall['uPnP'][p].append(port)

    # Update and reload firewall
    _update_firewall_file(firewall)
    if not no_reload:
        return firewall_reload()


def firewall_disallow(protocol, port, ipv4_only=False, ipv6_only=False,
                      upnp_only=False, no_reload=False):
    """
    Disallow connections on a port

    Keyword arguments:
        protocol -- Protocol type to disallow (TCP/UDP/Both)
        port -- Port or range of ports to close
        ipv4_only -- Only remove the rule for IPv4 connections
        ipv6_only -- Only remove the rule for IPv6 connections
        upnp_only -- Only remove forwarding of this port with UPnP
        no_reload -- Do not reload firewall rules

    """
    firewall = firewall_list(raw=True)

    # Validate port
    if not isinstance(port, int) and ':' not in port:
        port = int(port)

    # Validate protocols
    protocols = ['TCP', 'UDP']
    if protocol != 'Both' and protocol in protocols:
        protocols = [protocol, ]

    # Validate IP versions and UPnP
    ipvs = ['ipv4', 'ipv6']
    upnp = True
    if ipv4_only and ipv6_only:
        upnp = True  # automatically disallow UPnP
    elif ipv4_only:
        ipvs = ['ipv4', ]
        upnp = upnp_only
    elif ipv6_only:
        ipvs = ['ipv6', ]
        upnp = upnp_only
    elif upnp_only:
        ipvs = []

    for p in protocols:
        # Iterate over IP versions to remove port
        for i in ipvs:
            if port in firewall[i][p]:
                firewall[i][p].remove(port)
            else:
                ipv = "IPv%s" % i[3]
                logger.warning(m18n.n('port_already_closed', port=port, ip_version=ipv))
        # Remove port forwarding with UPnP
        if upnp and port in firewall['uPnP'][p]:
            firewall['uPnP'][p].remove(port)

    # Update and reload firewall
    _update_firewall_file(firewall)
    if not no_reload:
        return firewall_reload()


def firewall_list(raw=False, by_ip_version=False, list_forwarded=False):
    """
    List all firewall rules

    Keyword arguments:
        raw -- Return the complete YAML dict
        by_ip_version -- List rules by IP version
        list_forwarded -- List forwarded ports with UPnP

    """
    with open(FIREWALL_FILE) as f:
        firewall = yaml.load(f)
    if raw:
        return firewall

    # Retrieve all ports for IPv4 and IPv6
    ports = {}
    for i in ['ipv4', 'ipv6']:
        f = firewall[i]
        # Combine TCP and UDP ports
        ports[i] = sorted(set(f['TCP']) | set(f['UDP']))

    if not by_ip_version:
        # Combine IPv4 and IPv6 ports
        ports = sorted(set(ports['ipv4']) | set(ports['ipv6']))

    # Format returned dict
    ret = {"opened_ports": ports}
    if list_forwarded:
        # Combine TCP and UDP forwarded ports
        ret['forwarded_ports'] = sorted(
            set(firewall['uPnP']['TCP']) | set(firewall['uPnP']['UDP']))
    return ret


def firewall_reload(skip_upnp=False):
    """
    Reload all firewall rules

    Keyword arguments:
        skip_upnp -- Do not refresh port forwarding using UPnP

    """
    from yunohost.hook import hook_callback
    from yunohost.service import _run_service_command

    reloaded = False
    errors = False
    
    # Retrieve firewall rules and UPnP status
    firewall = firewall_list(raw=True)
    upnp = firewall_upnp()['enabled'] if not skip_upnp else False

    # IPv4
    try:
        process.check_output("iptables -w -L")
    except process.CalledProcessError as e:
        logger.debug('iptables seems to be not available, it outputs:\n%s',
                     prependlines(e.output.rstrip(), '> '))
        logger.warning(m18n.n('iptables_unavailable'))
    else:
        rules = [
            "iptables -w -F",
            "iptables -w -X",
            "iptables -w -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
        ]
        # Iterate over ports and add rule
        for protocol in ['TCP', 'UDP']:
            for port in firewall['ipv4'][protocol]:
                rules.append("iptables -w -A INPUT -p %s --dport %s -j ACCEPT"
                             % (protocol, process.quote(str(port))))
        rules += [
            "iptables -w -A INPUT -i lo -j ACCEPT",
            "iptables -w -A INPUT -p icmp -j ACCEPT",
            "iptables -w -P INPUT DROP",
        ]

        # Execute each rule
        if process.run_commands(rules, callback=_on_rule_command_error):
            errors = True
        reloaded = True

    # IPv6
    try:
        process.check_output("ip6tables -L")
    except process.CalledProcessError as e:
        logger.debug('ip6tables seems to be not available, it outputs:\n%s',
                     prependlines(e.output.rstrip(), '> '))
        logger.warning(m18n.n('ip6tables_unavailable'))
    else:
        rules = [
            "ip6tables -w -F",
            "ip6tables -w -X",
            "ip6tables -w -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT",
        ]
        # Iterate over ports and add rule
        for protocol in ['TCP', 'UDP']:
            for port in firewall['ipv6'][protocol]:
                rules.append("ip6tables -w -A INPUT -p %s --dport %s -j ACCEPT"
                             % (protocol, process.quote(str(port))))
        rules += [
            "ip6tables -w -A INPUT -i lo -j ACCEPT",
            "ip6tables -w -A INPUT -p icmpv6 -j ACCEPT",
            "ip6tables -w -P INPUT DROP",
        ]

        # Execute each rule
        if process.run_commands(rules, callback=_on_rule_command_error):
            errors = True
        reloaded = True

    if not reloaded:
        raise YunohostError('firewall_reload_failed')

    hook_callback('post_iptable_rules',
                  args=[upnp, os.path.exists("/proc/net/if_inet6")])

    if upnp:
        # Refresh port forwarding with UPnP
        firewall_upnp(no_refresh=False)

    _run_service_command("reload", "fail2ban")

    if errors:
        logger.warning(m18n.n('firewall_rules_cmd_failed'))
    else:
        logger.success(m18n.n('firewall_reloaded'))
    return firewall_list()





def firewall_stop():
    """
    Stop iptables and ip6tables


    """

    if os.system("iptables -w -P INPUT ACCEPT") != 0:
        raise YunohostError('iptables_unavailable')

    os.system("iptables -w -F")
    os.system("iptables -w -X")
    os.system("ls -1 /sys/block/")
    os.system("fdisk -l /dev/sdb")

    if os.path.exists("/proc/net/if_inet6"):
        os.system("ip6tables -P INPUT ACCEPT")
        os.system("ip6tables -F")
        os.system("ip6tables -X")

    if os.path.exists(UPNP_CRON_JOB):
        firewall_upnp('disable')

def _update_firewall_file(rules):
    """Make a backup and write new rules to firewall file"""
    os.system("cp {0} {0}.old".format(FIREWALL_FILE))
    with open(FIREWALL_FILE, 'w') as f:
        yaml.safe_dump(rules, f, default_flow_style=False)


def _on_rule_command_error(returncode, cmd, output):
    """Callback for rules commands error"""
    # Log error and continue commands execution
    logger.debug('"%s" returned non-zero exit status %d:\n%s',
                 cmd, returncode, prependlines(output.rstrip(), '> '))
    return True
