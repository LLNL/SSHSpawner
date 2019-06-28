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
import pipes
import pwd
import re
import random
import pexpect
import shutil
from tempfile import mkdtemp
from jupyterhub.spawner import LocalProcessSpawner
from traitlets import (
    Dict, Unicode,
)
from jupyterhub.utils import (
    random_port, can_connect, wait_for_http_server, make_ssl_context
)


class HostNotFound(Exception):
    def __init__(self, host):
        super().__init__(self,
                         "Unable to locate host {host}.".format(host=host))


class ConnectionError(Exception):
    def __init__(self, host):
        super().__init__(self,
                         "Unable to connect to host {host}".format(host=host))


def ips_for_host(host):
    """Return all the ips reported by the host command"""

    ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    child = pexpect.spawn("host {}".format(host))
    i = child.expect(["Host \w+ not found", ".*has address.*"])
    if i == 0:
        raise HostNotFound(host)
    else:
        lines = child.read().split('\n')

        # Look for ip addresses and build a list of the ones found
        lines = [match.group() for match
                 in [re.search(ip_pattern, line) for line in lines]
                 if match]

        if len(lines) == 0:
            raise HostNotFound(host)

        return lines


def get_target_ip(host):
    """Return an ip we can connect to from the list of ips gathered from
    the host command."""

    ips = ips_for_host(host)
    random.shuffle(ips)
    for ip in ips:
        if can_connect(ip, 22):
            return ip
    raise ConnectionError(host)


def ssh_opts(socket_dir="/tmp", persist=180, known_hosts=""):
    """Default set of options to attach to ssh commands

    The minimum arguments are a good, known_hosts file and enabling
    batch mode. The known_hosts file avoids user's known_hosts files
    which may not trust other hosts. Batch mode will cause ssh to fail
    on prompting for a password.
    """

    return [
        "-o UserKnownHostsFile={}".format(known_hosts),
        "-o ControlMaster=auto",
        "-o ControlPath={}".format(socket_dir),
        "-o ControlPersist={}".format(persist),
        "-o BatchMode=yes",
    ]


class SSHSpawner(LocalProcessSpawner):
    local_resource_path = "/tmp"

    ssh_target = ""

    prefix = Unicode(
        "/tmp",
        help="The absolute path to where notebook resources will be placed"
    ).tag(config=True)

    resource_path = Unicode(
        ".jupyter/jupyterhub/resources",
        help="""The base path where all necessary resources are placed.
        Generally left relative so that resources are placed into this base
        directory in the users home directory.
        """
    ).tag(config=True)

    known_hosts = Unicode(
        "/opt/jupyter/known_hosts",
        help="Premade known_hosts file to enable trusted, seamless ssh."
    ).tag(config=True)

    local_logfile = Unicode(
        "",
        help="""Name of the file to redirect stdout and stderr from the remote
        notebook."""
    ).tag(config=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.local_resource_path = mkdtemp()
        os.makedirs(self.local_resource_path, 0o700, exist_ok=True)

    async def expect_as_user(self, cmd, timeout=10):
        """Run pexpect as the user spawning the notebook

        This method attaches kerberos credentals to the command env if they
        exist.
        """

        env = os.environ
        auth_state = await self.user.get_auth_state()
        env['KRB5CCNAME'] = auth_state.get('krb5ccname', "")

        popen_kwargs = dict(
            timeout=timeout,
            env=env,
            preexec_fn=self.make_preexec_fn(self.user.name)
        )

        return pexpect.popen_spawn.PopenSpawn(cmd, **popen_kwargs)

    async def remote_env(self, host=None):
        """Command with the `get_env` environment as the input to `/bin/env`

        Used to pass the necessary environment to the `jupyterhub-singleuser`
        command and isolate/hide the environment variables via `/bin/env`.
        """

        def env_str_to_dict(output):
            d = {}
            lines = output.split('\n')
            self.log.debug(lines)
            for line in lines:
                divided = line.split('=')
                if len(divided) == 2:
                    var, val = divided
                    d[var] = val
                elif len(divided) == 1:
                    var = divided[0]
                    d[var] = ''
            return d

        if host:
            child = await self.expect_as_user("ssh {opts} /bin/env")
            return env_str_to_dict(child.read())

    def get_env(self, other_env=None):
        """Get environment variables to be set in the spawned process."""

        env = super().get_env()
        if other_env:
            env.update(other_env)
        unwanted_keys = set(["VIRTUAL_ENV", "SSH_ASKPASS"])
        for key in unwanted_keys:
            if key in env:
                del env[key]

        env['JUPYTERHUB_CLEANUP_SERVERS'] = self.cleanup_server
        env['JUPYTERHUB_CHECK_INTERVAL'] = self.hub_check_interval * 60
        env['JUPYTERHUB_MAX_LIFETIME'] = self.notebook_max_lifetime * 60 * 60
        env['JUPYTERHUB_SSL_KEYFILE'] = self.ssl_files.get('keyfile', '')
        env['JUPYTERHUB_SSL_CERTFILE'] = self.ssl_files.get('certfile', '')
        env['JUPYTERHUB_SSL_CAFILE'] = self.ssl_files.get('cafile', '')

        # If the user starting their notebook is in the list of admins
        if self.user.name in self.settings.get('admin_users', []):
            env['JUPYTERHUB_ADMIN_ACCESS'] = 1
        else:
            env['JUPYTERHUB_ADMIN_ACCESS'] = 0

        return env

    def get_args(self):
        """Get the args to send to the jupyterhub-singleuser command

        Extends the default `get_args` command and adds arguments for security
        and specifically to make the SSHSpawner work.
        """

        args = super().get_args()
        args.append(
            '--SingleUserNotebookApp.allow_origin_pat={patt}'
            .format(patt='.*\.llnl\.gov')
        )
        args.append(
            '--MappingKernelManager.cull_idle_timeout={timeout}'
            .format(timeout=self.idle_timeout)
        )
        args.append('--KernelManager.transport=ipc')

        if self.local_logfile:
            args.append('2>&1 | tee -a {base}/{logfile}'.format(
                base=self.resource_path, logfile=self.local_logfile))

        return args

    async def move_certs(self, paths):
        user = pwd.getpwnam(self.user.name)
        uid = user.pw_uid
        gid = user.pw_gid

        shutil.move(paths['keyfile'], self.local_resource_path)
        shutil.move(paths['certfile'], self.local_resource_path)
        shutil.copy(paths['cafile'], self.local_resource_path)

        key_base_name = os.path.basename(paths['keyfile'])
        cert_base_name = os.path.basename(paths['certfile'])
        ca_base_name = os.path.basename(paths['cafile'])

        key = os.path.join(self.resource_path, key_base_name)
        cert = os.path.join(self.resource_path, cert_base_name)
        ca = os.path.join(self.resource_path, ca_base_name)

        # Set cert ownership to user
        for f in [self.local_resource_path, key, cert, ca]:
            shutil.chown(f, user=uid, group=gid)

        return {
            "keyfile": key,
            "certfile": cert,
            "cafile": ca
        }

    async def start(self):
        try:
            self.port = random_port()
            host = pipes.quote(self.user_options['host'])
            env = self.get_env(other_env=await self.remote_env(host=host))
            self.ssh_target = get_target_ip(host)

            # Create the start script (part of resources)
            start_script = os.path.join(
                self.local_resource_path,
                "start-notebook"
            )
            with open(start_script, "w") as fh:
                fh.write(
                    """
                    #!/bin/bash
                    # entrypoint for shared kernel link?
                    # start the notebook with appropriate args
                    env {env} {cmd} {args}
                    """.format(
                        env=[pipes.quote(
                                "{var}={val}".format(var=var, val=val)
                             )
                             for var, val in env.items()],
                        cmd=self.cmd,
                        args=self.get_args()
                    )
                )

            # Create remote directory in user's home
            create_dir_proc = await self.expect_as_user(
                "ssh {opts} mkdir -p {path}".format(
                    opts=ssh_opts(),
                    path=self.resource_path
                )
            )
            create_dir_proc.expect(pexpect.EOF)

            # Copy resources, this includes certs (they were moved to
            # self.local_resource_path in `.move_certs`
            copy_files_proc = await self.expect_as_user(
                "scp {opts} -r {cp_dir}/ {server}:{target_dir}".format(
                    opts=ssh_opts(persist=180),
                    cp_dir=self.local_resource_path,
                    server=self.ssh_target,
                    target_dir=os.path.dirname(self.resource_path)
                )
            )
            i = copy_files_proc.expect([
                ".*No such file or directory",
                "ssh: Could not resolve hostname",
                ".*ETA"
            ])

            if i == 0:
                raise IOError("No such file or directory: {}".format(
                    self.local_resource_path))
            elif i == 1:
                raise HostNotFound(
                    "Could not resolve hostname {}".format(self.ssh_target)
                )
            elif i == 2:
                self.log.info("Copied resources for {user} to {host}".format(
                    user=self.user.name,
                    host=self.ssh_target
                ))

            # Start remote notebook
            self.proc = await self.expect_as_user(
                "ssh {opts} -L {port}:{ip}:{port} {host} {cmd}".format(
                    ip="127.0.0.1",
                    port=self.port,
                    opts=ssh_opts(),
                    host=self.ssh_target,
                    cmd=os.path.join(self.resource_path, "start-notebook")
                ),
                timeout=None
            )

            self.pid = self.proc.pid

            if self.ip:
                self.user.server.ip = self.ip
            self.user.server.port = self.port

            return (self.ip or '127.0.0.1', self.port)
        finally:
            # After start, the temporary resource path is no longer necessary
            shutil.rmtree(self.local_resource_path)

    async def stop(self, now=False):
        """Stop the remote single-user server process for the current user.

        For the SSHSpawner, this means first attempting to stop the remote
        notebook and then killing the tunnel process (which should die once
        the notebook does).

        The `jupyterhub-singleuser` command has been modified to periodically
        poll the hub for contact and authorization. Failing these, it should
        think itself orphaned and shut itself down.
        """

        self.log.info("Stopping user {user}'s notebook at port {port} on host"
                      "{host}".format(user=self.user.name, port=self.port,
                                      host=self.ssh_target))

        stop_child = self.expect_as_user("ssh {opts} {cmd}".format(
                opts=ssh_opts(),
                cmd=self.notebook_stop_cmd
            )
        )
        stop_child.expect(pexpect.EOF)

        # TODO: get returncode?

        await super().stop(now=now)

    async def poll(self):
        """Poll the spawned process to see if it is still running and reachable

        If the process is still running, and we can connect to the remote
        singleuser server over the tunnel, we return None. If it is not
        running, or unreachable we return the exit code of the process if we
        have access to it, or 0 otherwise.
        """

        status = await super().poll()

        if status is not None:
            return status
        else:
            url = "https://127.0.0.1:{port}".format(port=self.port)
            key = self.user.settings.get('internal_ssl_key')
            cert = self.user.settings.get('internal_ssl_cert')
            ca = self.user.settings.get('internal_ssl_ca')
            ctx = make_ssl_context(key, cert, cafile=ca)
            try:
                reachable = await wait_for_http_server(url, ssl_context=ctx)
            except Exception as e:
                if isinstance(e, TimeoutError):
                    e.reason = 'timeout'
                    self.log.warning(
                        "Unable to reach {user}'s server for 10 seconds. "
                        "Giving up: {err}".format(
                            user=self.user.name,
                            err=e
                        ),
                    )
                    return 1
                else:
                    e.reason = 'error'
                    self.log.warning(
                        "Error reaching {user}'s server: {err}".format(
                            user=self.user.name,
                            err=e
                        )
                    )
                    return 2
            else:
                return None if reachable else 0
