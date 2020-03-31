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
import stat
import pexpect
import shutil
import signal
from glob import glob
from urllib.parse import urlparse, urlunparse
from pexpect import popen_spawn
from tempfile import TemporaryDirectory
from jupyterhub.spawner import LocalProcessSpawner
from traitlets import default
from traitlets import (
    Bool, Integer, Unicode, Int, List
)
from jupyterhub.utils import (
    random_port, can_connect, wait_for_http_server, make_ssl_context
)

_script_template = """#!/bin/bash
# entrypoint for shared kernel link?
# start the notebook with appropriate args
{}
"""


class HostNotFound(Exception):
    def __init__(self, host):
        super().__init__(self,
                         "Unable to locate host {host}.".format(host=host))


class ConnectionError(Exception):
    def __init__(self, host):
        super().__init__(self,
                         "Unable to connect to host {host}".format(host=host))


class SSHSpawner(LocalProcessSpawner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        user = pwd.getpwnam(self.user.name)
        self.uid = user.pw_uid
        self.gid = user.pw_gid
        self.ssh_target = ""
        os.makedirs(self.local_resource_path, 0o700, exist_ok=True)

    resource_path = Unicode(
        ".jupyter/jupyterhub/resources",
        help="""The base path where all necessary resources are placed.
        Generally left relative so that resources are placed into this base
        directory in the users home directory.
        """
    ).tag(config=True)

    hostname = Unicode(
        "",
        help="Hostname of the hub host. Useful if the Hub is in a container."
    ).tag(config=True)

    known_hosts = Unicode(
        "/opt/jupyter/known_hosts",
        help="Premade known_hosts file to enable trusted, seamless ssh."
    ).tag(config=True)

    ssh_hosts = List(
        [],
        help="List of available hosts to ssh to."
    ).tag(config=True)

    allow_origin_pattern = Unicode(
        "",
        help="Pattern for CORS requests (when behind a reverse proxy)"
    ).tag(config=True)

    local_logfile = Unicode(
        "",
        help="""Name of the file to redirect stdout and stderr from the remote
        notebook."""
    ).tag(config=True)

    ssh_control_persist_time = Int(
        1,
        help="""The amount of time for SSH connections over the control master
        will stay active"""
    ).tag(config=True)

    cleanup_server = Bool(
        True,
        help="Teardown the notebook server when contact is lost with the hub."
    ).tag(config=True)

    hub_check_interval = Integer(
        5,
        help="Interval in minutes to check if notebook has been orphaned."
    ).tag(config=True)

    notebook_max_lifetime = Integer(
        12,
        help="Max lifetime in hours for a remotely spawned notebook to live."
    ).tag(config=True)

    idle_timeout = Integer(
        300,
        help="""The amount of time before culling an idle kernel."""
    ).tag(config=True)

    start_notebook_cmd = Unicode(
        "start-notebook",
        help="""The command to run to start a notebook"""
    ).tag(config=True)

    stop_notebook_cmd = Unicode(
        "stop-notebook",
        help="""The command to run to stop a running notebook"""
    ).tag(config=True)

    @property
    def local_resource_path(self):
        return "/tmp/{user}".format(user=self.user.name)

    @property
    def ssh_socket(self):
        name = "{user}@{host}".format(
            user=self.user.name,
            host=self.ssh_target
        )

        return os.path.join(self.local_resource_path, name)

    @property
    def start_script(self):
        return os.path.join(
            self.local_resource_path,
            self.start_notebook_cmd
        )

    def get_user_ssh_hosts(self):
        return self.ssh_hosts

    @default('options_form')
    def _options_form(self):
        """Populate a list of ssh targets on the pre_spawn form"""

        hosts = self.get_user_ssh_hosts()
        if not hosts:
            return """
            <label for="host">Input host for notebook launch:</label>
            <input type="text" name="host" class="form-control">
            """
        host_option_template = '<option value="{host}">{host}</option>'
        host_option_tags = []
        for host in hosts:
            host_option_tags.append(
                host_option_template.format(host=host))
        options = ''.join(host_option_tags)

        return """
        <label for="host">Select host for notebook launch:</label>
        <select name="host" class="form-control">{options}</select>
        """.format(options=options)

    def options_from_form(self, formdata):
        """Turn html formdata from `options_form` into a dict for later use"""

        options = {}
        options['host'] = pipes.quote(formdata.get('host', [''])[0].strip())
        return options

    def ips_for_host(self, host):
        """Return all the ips reported by the host command"""

        ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        child = pexpect.spawn("host {}".format(host), encoding="utf-8")
        i = child.expect([r"Host \w+ not found", ".*has address.*"])
        if i == 0:
            raise HostNotFound(host)
        else:
            lines = child.after.split('\n')

            # Look for ip addresses and build a list of the ones found
            lines = [match.group() for match
                     in [re.search(ip_pattern, line) for line in lines]
                     if match]

            if len(lines) == 0:
                raise HostNotFound(host)

            return lines

    def ssh_opts(self, persist=180,
                 known_hosts="", batch_mode=True, other_opts=None):
        """Default set of options to attach to ssh commands

        The minimum arguments are a good, known_hosts file and enabling
        batch mode. The known_hosts file avoids user's known_hosts files
        which may not trust other hosts. Batch mode will cause ssh to fail
        on prompting for a password.

        This implementation also uses ssh ControlMaster to speed up and
        simplify repeated operations over SSH.
        """

        opts = {
            "ControlMaster": "auto",
            "ControlPath": "/tmp/%r@%h",
            "ControlPersist": persist,
            "BatchMode": batch_mode,
        }

        if known_hosts:
            opts["UserKnownHostsFile"] = known_hosts
        else:
            self.log.warning("Skipping host key check")
            opts["StrictHostKeyChecking"] = "no"

        if other_opts:
            opts.extend(other_opts)

        tmpl = "-o {opt}={val}"
        return ' '.join(
                [tmpl.format(opt=opt, val=val) for opt, val in opts.items()])

    def spawn_as_user(self, cmd, timeout=10):
        """Run pexpect as the user spawning the notebook

        This method attaches kerberos credentals to the command env if they
        exist.
        """

        env = os.environ
        krb_files = glob("/tmp/krb5cc_{uid}*".format(uid=self.uid))
        if krb_files:
            env["KRB5CCNAME"] = "FILE:" + max(krb_files, key=os.path.getctime)

        popen_kwargs = dict(
            env=env,
            timeout=timeout,
            encoding="utf-8",
            preexec_fn=self.make_preexec_fn(self.user.name)
        )

        self.log.debug("Running: {cmd} as {user}".format(
                cmd=cmd,
                user=self.user.name))
        return popen_spawn.PopenSpawn(cmd, **popen_kwargs)

    async def remote_env(self, host=None):
        """Command with the `get_env` environment as the input to `/bin/env`

        Used to pass the necessary environment to the `jupyterhub-singleuser`
        command and isolate/hide the environment variables via `/bin/env`.
        """

        def env_str_to_dict(output):
            "Convert the output of `env` into a dict"

            d = {}
            lines = output.split('\n')
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
            opts = self.ssh_opts(
                known_hosts=self.known_hosts
            )
            self.log.info("Collecting remote environment from {}".format(host))
            child = self.spawn_as_user(
                "ssh {opts} {host} env".format(opts=opts, host=host)
            )
            child.expect(pexpect.EOF)
            return env_str_to_dict(child.before)

    def ip_for_host(self, host):
        """Return an ip for a given host

        This method is meant to pick from a series of ips that come back from
        invoking the host command. This could be used to implement load
        balancing.
        """

        ips = self.ips_for_host(host)
        random.shuffle(ips)
        for ip in ips:
            if can_connect(ip, 22):
                return ip
        raise ConnectionError(host)

    def get_env(self, other_env=None):
        """Get environment variables to be set in the spawned process."""

        def swap_host(url, hostname=""):
            if not hostname:
                return url
            parsed = urlparse(url)
            parsed = parsed._replace(netloc=hostname + ":" + str(parsed.port))
            return urlunparse(parsed)

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

        # This is to account for running JupyterHub in a container since the
        # container hostname will be meaningless.
        env['JUPYTERHUB_API_URL'] = swap_host(
            env['JUPYTERHUB_API_URL'],
            hostname=self.hostname
        )

        env['JUPYTERHUB_ACTIVITY_URL'] = swap_host(
            env['JUPYTERHUB_ACTIVITY_URL'],
            hostname=self.hostname
        )

        # If the user starting their notebook is in the list of admins
        if self.user.name in self.user.settings.get('admin_users', []):
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
        if self.allow_origin_pattern:
            args.append(
                '--SingleUserNotebookApp.allow_origin_pat={patt}'
                .format(patt=self.allow_origin_pattern)
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

    def stage_certs(self, paths, dest):
        shutil.move(paths['keyfile'], dest)
        shutil.move(paths['certfile'], dest)
        shutil.copy(paths['cafile'], dest)

        key_base_name = os.path.basename(paths['keyfile'])
        cert_base_name = os.path.basename(paths['certfile'])
        ca_base_name = os.path.basename(paths['cafile'])

        key = os.path.join(self.resource_path, key_base_name)
        cert = os.path.join(self.resource_path, cert_base_name)
        ca = os.path.join(self.resource_path, ca_base_name)

        return {
            "keyfile": key,
            "certfile": cert,
            "cafile": ca,
        }

    async def create_start_script(self, remote_env=None):
        env = self.get_env(other_env=remote_env)
        quoted_env = ["env"] +\
                     [pipes.quote("{var}={val}".format(var=var, val=val))
                      for var, val in env.items()]
        # environment + cmd + args
        cmd = quoted_env + self.cmd + self.get_args()

        with open(self.start_script, "w") as fh:
            fh.write(
                _script_template.format(' '.join(cmd))
            )
            shutil.chown(self.start_script, user=self.uid, group=self.gid)
            os.chmod(
                self.start_script,
                stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
            )

    def startup_files(self):
        return [os.path.join(self.local_resource_path, f)
                for f in os.listdir(self.local_resource_path)]

    def fixperms(self):
        # Set proper ownership to the user we'll run as
        resources = [self.local_resource_path] + self.startup_files()
        for resource in resources:
            shutil.chown(resource, user=self.uid, group=self.gid)

    def map_to_remote_path(self, filename):
        return os.path.join(self.resource_path, os.path.basename(filename))

    def map_to_local_path(self, filename):
        return os.path.join(self.resource_path, os.path.basename(filename))

    async def start(self):

        self.port = random_port()
        host = pipes.quote(self.user_options['host'])
        self.ssh_target = self.ip_for_host(host)
        remote_env = await self.remote_env(host=self.ssh_target)
        opts = self.ssh_opts(
            persist=self.ssh_control_persist_time,
            known_hosts=self.known_hosts
        )

        self.cert_paths = self.stage_certs(
            self.cert_paths,
            self.local_resource_path
        )

        # Create the start script (part of resources)
        await self.create_start_script(remote_env=remote_env)

        self.fixperms()

        # Create remote directory in user's home
        create_dir_proc = self.spawn_as_user(
            "ssh {opts} {host} mkdir -p {path}".format(
                opts=opts,
                host=self.ssh_target,
                path=self.resource_path
            )
        )
        create_dir_proc.expect(pexpect.EOF)

        copy_files_proc = self.spawn_as_user(
            "scp {opts} {files} {host}:{target_dir}/".format(
                opts=opts,
                files=' '.join(self.startup_files()),
                cp_dir=self.local_resource_path,
                host=self.ssh_target,
                target_dir=self.resource_path
            )
        )
        i = copy_files_proc.expect([
            ".*No such file or directory",
            "ssh: Could not resolve hostname",
            pexpect.EOF,
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
        start_notebook_child = self.spawn_as_user(
            "ssh {opts} -L {port}:{ip}:{port} {host} {cmd}".format(
                ip="127.0.0.1",
                port=self.port,
                opts=opts,
                host=self.ssh_target,
                cmd=os.path.join(self.resource_path,
                                 self.start_notebook_cmd)
            ),
            timeout=None
        )

        self.proc = start_notebook_child.proc
        self.pid = self.proc.pid

        if self.ip:
            self.user.server.ip = self.ip
        self.user.server.port = self.port

        return (self.ip or '127.0.0.1', self.port)

    async def stop(self, now=False):
        """Stop the remote single-user server process for the current user.

        For the SSHSpawner, this means first attempting to stop the remote
        notebook and then killing the tunnel process (which should die once
        the notebook does).

        The `jupyterhub-singleuser` command has been modified to periodically
        poll the hub for contact and authorization. Failing these, it should
        think itself orphaned and shut itself down.
        """

        status = await self.poll()
        if status is not None:
            return
        self.log.info("Stopping user {user}'s notebook at port {port} on host "
                      "{host}".format(user=self.user.name, port=self.port,
                                      host=self.ssh_target))

        stop_child = self.spawn_as_user("ssh {opts} {host} {cmd}".format(
                opts=self.ssh_opts(known_hosts=self.known_hosts),
                host=self.ssh_target,
                cmd=self.stop_notebook_cmd
            )
        )
        stop_child.expect(pexpect.EOF)
        ret_code = stop_child.wait()
        if ret_code == 0:
            self.log.info("Notebook stopped")

        self.log.debug("Killing %i", self.pid)
        await self._signal(signal.SIGKILL)

        # close the tunnel
        os.remove(self.ssh_socket)

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
        elif not os.path.exists(self.ssh_socket):
            # tunnel is closed or non-existent
            return 0
        else:
            protocol = "http" if not self.user.settings["internal_ssl"] \
                       else "https"
            url = "{protocol}://{ip}:{port}".format(
                        protocol=protocol,
                        ip=(self.ip or '127.0.0.1'),
                        port=self.port
                  )
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
