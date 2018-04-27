#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
sys.dont_write_bytecode = True

from pprint import pprint

class InventorySpecifiedError(Exception):
    def __init__(self):
        message = 'do not specify inventory; script will generate it'
        super(InventorySpecifiedError, self).__init__(message)

class ModuleArgsSpecifiedError(Exception):
    def __init__(self):
        message = 'do not specify module args; script will generate it'
        super(ModuleArgsSpecifiedError, self).__init__(message)

def get_pkgs2hosts(vulns):
    pkgs2hosts  = {}
    regex = re.compile('([^,]+),([^,]+),([^,]+)')
    for vuln in vulns:
        match = regex.search(vuln)
        if match:
            host, _, pkgs = match.groups()
            pkgs2hosts[pkgs] = pkgs2hosts.get(pkgs, []) + [host]
    return pkgs2hosts

def gen_cmds(pkgs2hosts, args):
    cmds = []
    for pkgs, hosts in pkgs2hosts.items():
        name = pkgs.replace(' ', '-') + '.hosts'
        yum = "sudo /usr/local/sbin/yum-wrapper update -y {pkgs}".format(**locals())
        with open(name, 'w') as f:
            f.write('\n'.join(hosts)+'\n')
        cmds += ["ansible -i {name} {args} -a '{yum}'".format(**locals())]
    return cmds

def v2a(vulns, args):
    pkgs2hosts = get_pkgs2hosts(vulns)
    cmds = gen_cmds(pkgs2hosts, args)
    print('\n'.join(cmds))

if __name__ == '__main__':
    vulns =sys.stdin.read().strip().split('\n')
    args = sys.argv[1:]
    if '-h' in args or '--help' in args:
        os.system('ansible --help')
        sys.exit(-1)
    elif '-i' in args:
        raise InventorySpecifiedError
    elif '-a' in args:
        raise ModuleArgsSpecifiedError
    v2a(vulns, ' '.join(args))
