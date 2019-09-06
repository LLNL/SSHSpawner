###############################################################################
# Copyright (c) 2018, Lawrence Livermore National Security, LLC
# Produced at the Lawrence Livermore National Laboratory
# Written by Thomas Mendoza mendoza33@llnl.gov
# LLNL-CODE-771750
# All rights reserved
#
# This file is part of SSHSpawner: https://github.com/LLNL/SSHSpawner
#
# SPDX-License-Identifier: BSD-3-Clause
###############################################################################

import os
import re
import sys
from tempfile import NamedTemporaryFile, mkstemp

from jupyterhub import orm
from jupyterhub.objects import Hub
from jupyterhub.user import User

from .. import SSHSpawner


_echo_sleep = """
import sys, time
print(sys.argv)
time.sleep(30)
"""


def new_spawner(db, **kwargs):
    user = kwargs.setdefault('user', User(db.query(orm.User).first(), {}))
    kwargs.setdefault('cmd', [sys.executable, '-c', _echo_sleep])
    kwargs.setdefault('hub', Hub())
    kwargs.setdefault('notebook_dir', os.getcwd())
    kwargs.setdefault('default_url', '/user/{username}/lab')
    kwargs.setdefault('oauth_client_id', 'mock-client-id')
    kwargs.setdefault('interrupt_timeout', 1)
    kwargs.setdefault('term_timeout', 1)
    kwargs.setdefault('kill_timeout', 1)
    kwargs.setdefault('poll_interval', 1)
    return user._new_spawner('', spawner_class=SSHSpawner, **kwargs)


async def test_ssh_opts(db, request):
    spawner = new_spawner(db)
    known_hosts = "/foo/bar/baz"
    persist = 42
    opts = spawner.ssh_opts(
        known_hosts=known_hosts,
        persist=persist
    )

    assert known_hosts in opts
    assert str(persist) in opts

    # falls back to no host checking
    no_check_opts = spawner.ssh_opts()

    assert "StrictHostKeyChecking=no" in no_check_opts


def test_ips_for_host(db):
    spawner = new_spawner(db)
    ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    ips = spawner.ips_for_host("example.com")

    assert len(ips) != 0
    assert any(re.search(ip_pattern, ip) for ip in ips)


async def test_spawn_as_user(db):
    spawner = new_spawner(db)

    child = spawner.spawn_as_user("env", timeout=2)
    out = child.read()
    lines = out.split("\n")

    assert len(lines) != 0


def test_get_env(db):
    other_env = {
        "FOO": "foo",
        "BAR": "bar",
        "JUPYTERHUB_ADMIN_ACCESS": 1,
    }
    spawner = new_spawner(db)

    env = spawner.get_env(other_env=other_env)

    assert env["FOO"] == "foo"
    assert env["BAR"] == "bar"
    assert env["JUPYTERHUB_ADMIN_ACCESS"] == 0

    # if they are an admin in the hub settings, they should get admin access
    spawner.user.settings['admin_users'] = [spawner.user.name]
    env = spawner.get_env(other_env=other_env)
    assert env["JUPYTERHUB_ADMIN_ACCESS"] == 1


def test_get_args(db):
    spawner = new_spawner(db)
    args = spawner.get_args()

    assert any(re.search("ipc", arg) for arg in args)
    assert not any(re.search("allow_origin", arg) for arg in args)

    # with extra settings, should get extra args
    spawner.local_logfile = "log.txt"
    spawner.allow_origin_pattern = r".*example.com"
    args = spawner.get_args()
    assert any(re.search("allow_origin", arg) for arg in args)
    assert any(re.search(spawner.local_logfile, arg) for arg in args)


async def test_create_start_script(db):
    spawner = new_spawner(db)

    with NamedTemporaryFile() as tf:
        await spawner.create_start_script(tf.name)
        with open(tf.name) as fh:
            script = fh.read()
            assert script
            assert "#!/bin/bash" in script
            assert any([
                    re.search(r"\s*env\s*", script, re.M),
                    re.search(r"\s*/bin/env\s*", script, re.M),
                    re.search(r"\s*/usr/bin/env\s*", script, re.M)
                ])
