import os
import stat
import pipes
import pwd
import shutil
import signal
import sys
import grp
import warnings
import shlex
import re
import socket
import random
import json
from subprocess import Popen, PIPE, TimeoutExpired
from tempfile import mkdtemp

from traitlets import default
from traitlets.config import LoggingConfigurable
from traitlets import (
    Any, Bool, Dict, Instance, Integer, Float, List, Unicode,
    validate,
)

from jupyterhub.utils import (
    random_port, url_path_join, can_connect, wait_for_http_server,
    make_ssl_context
)
from jupyterhub.spawner import LocalProcessSpawner
from certipy import Certipy

class HostNotFound(Exception):
    def __init__(self, host):
        super().__init__(self,
                         "Unable to locate host {host}.".format(host=host))


class ConnectionError(Exception):
    def __init__(self, host):
        super().__init__(self,
                         "Unable to connect to host {host}".format(host=host))


class SSHSpawner(LocalProcessSpawner):
    ssl_files = Dict()

    _kerberos_filename = ''

    ssh_target = Unicode('',
        help="""The fqdn or ip address of the host being ssh'ed to.""",
    )

    jupyter_path = Unicode('',
        help="Defines extra search paths for Jupyter data (kernelspecs, etc)."
    ).tag(config=True)

    cleanup_server = Bool(True,
        help="Teardown the notebook server when contact is lost with the hub."
    ).tag(config=True)

    hub_check_interval = Integer(5,
        help="Interval in minutes to check if notebook has been orphaned."
    ).tag(config=True)

    notebook_max_lifetime = Integer(12,
        help="Max lifetime in hours for a remotely spawned notebook to live."
    ).tag(config=True)

    known_hosts = Unicode('/opt/jupyter/known_hosts',
        help="Premade known_hosts file to enable trusted, seamless ssh."
    ).tag(config=True)

    resource_path = Unicode('.jupyter/jupyterhub/resources',
        help="""The base path where all necessary resources are placed.
        Generally left relative so that resources are placed into this base
        directory in the users home directory.
        """
    ).tag(config=True)

    start_notebook_cmd = Unicode('start-notebook',
        help="""The command used to start a notebook."""
    ).tag(config=True)

    notebook_stop_cmd = Unicode('stop-notebook',
        help="""The command used to interface with a notebook."""
    ).tag(config=True)

    local_logfile = Unicode('',
        help="""Name of the file to redirect stdout and stderr from the remote
        notebook."""
    ).tag(config=True)

    get_hosts_cmd = Unicode('',
        help="""Optional command to retrieve ssh hosts available to a user."""
    ).tag(config=True)

    idle_timeout = Integer(300,
        help="""The amount of time before culling an idle kernel."""
    ).tag(config=True)

    spawn_error_timeout = Integer(3,
        help="""The time in seconds to wait for errors when spawning."""
    ).tag(config=True)

    def get_user_ssh_hosts(self):
        """Return a list of hosts the user can ssh to"""

        if not self.get_hosts_cmd:
            return

        proc = self.exec_as_spawning_user(shlex.split(self.get_hosts_cmd))
        try:
            out, err = proc.communicate(timeout=self.spawn_error_timeout)

            if err:
                stripped_err = err.decode().strip()
                self.log.error(stripped_err)
            if out:
                envelope = json.loads(out.decode().strip())
                return envelope['output'].get('accounts', None)
        except TimeoutExpired:
            self.log.error("Unable to invoke {cmd} to get {user}'s SSH hosts"
                           .format(cmd=self.get_hosts_cmd,
                                   user=self.user.name))

    def ssh_opts(self):
        """Default set of options to attach to ssh commands

        The minimum arguments are a good, known_hosts file and enabling
        batch mode. The known_hosts file avoids user's known_hosts files
        which may not trust other hosts. Batch mode will cause ssh to fail
        on prompting for a password.
        """
        return [
            ("-o UserKnownHostsFile={known_hosts}"
             .format(known_hosts=self.known_hosts)),
            "-o BatchMode=yes",
        ]

    @default('options_form')
    def _options_form(self):
        hosts = self.get_user_ssh_hosts()
        if not hosts:
            # FIXME: Need a better way of testing this ahead of time and
            # simply invalidating a users session...
            return """
            <p>Unable to get SSH targets</p>
            <p>This happens when your kerberos tickets expire.</p>
            <p>Log out and log back in again to regenerate them.</p>
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
        options['host'] = formdata.get('host', [''])[0].strip()
        return options

    def get_env(self, other_env=None):
        """Get environment variables to be set in the spawned process."""

        env = super().get_env()
        if other_env:
            env.update(other_env)
        unwanted_keys = set(["VIRTUAL_ENV", "SSH_ASKPASS"])
        for key in unwanted_keys:
            if key in env:
                del env[key]

        max_lifetime_seconds = self.notebook_max_lifetime * 60 * 60
        hub_check_seconds = self.hub_check_interval * 60

        env['JUPYTER_PATH'] = self.jupyter_path
        env['JUPYTERHUB_CLEANUP_SERVERS'] = self.cleanup_server
        env['JUPYTERHUB_CHECK_INTERVAL'] = hub_check_seconds
        env['JUPYTERHUB_MAX_LIFETIME'] = max_lifetime_seconds
        env['JUPYTERHUB_SSL_KEYFILE'] = self.ssl_files.get('keyfile', '')
        env['JUPYTERHUB_SSL_CERTFILE'] = self.ssl_files.get('certfile', '')
        env['JUPYTERHUB_SSL_CAFILE'] = self.ssl_files.get('cafile', '')

        # Never
        env['JUPYTERHUB_ADMIN_ACCESS'] = 0
        return env

    def move_certs(self, paths):
        """Moves, sets up proper ownership for given cert paths"""

        user = pwd.getpwnam(self.user.name)
        uid = user.pw_uid
        gid = user.pw_gid
        home = user.pw_dir

        # Create dir for user's certs wherever we're starting
        out_dir = "{home}/{out}".format(home=home, out=self.resource_path)
        shutil.rmtree(out_dir, ignore_errors=True)
        os.makedirs(out_dir, 0o700, exist_ok=True)

        # FIXME: Faster than some boilerplate recursive directory walk, but
        # a little sad there's no way to ensure that the resource_path has
        # correct permissions if its depth > 1...
        rpath = home
        for d in self.resource_path.split("/"):
            rpath += "/" + d
            shutil.chown(rpath, user=uid, group=gid)

        # Move certs to users dir
        shutil.move(paths['keyfile'], out_dir)
        shutil.move(paths['certfile'], out_dir)
        shutil.copy(paths['cafile'], out_dir)

        key_base_name = os.path.basename(paths['keyfile'])
        cert_base_name = os.path.basename(paths['certfile'])
        ca_base_name = os.path.basename(paths['cafile'])

        key = os.path.join(out_dir, key_base_name)
        cert = os.path.join(out_dir, cert_base_name)
        ca = os.path.join(out_dir, ca_base_name)

        # Set cert ownership to user
        for f in [out_dir, key, cert, ca]:
            shutil.chown(f, user=uid, group=gid)

        self.ssl_files = {
            "keyfile": self.resource_path + '/' + key_base_name,
            "certfile": self.resource_path + '/' + cert_base_name,
            "cafile": self.resource_path + '/' + ca_base_name,
        }

        return self.ssl_files

    def exec_as_spawning_user(self, cmd, new_session=False):
        """Run a command as the user spawning the notebook

        This method attaches kerberos credentals to the command env.
        """

        env = os.environ
        krb_file = self.get_krb_file()
        env['KRB5CCNAME'] = "FILE:/tmp/{filename}".format(filename=krb_file)

        popen_kwargs = dict(
            stdout=PIPE,
            stderr=PIPE,
            env=env,
            start_new_session=new_session,
            preexec_fn=self.make_preexec_fn(self.user.name)
        )
        return Popen(cmd, **popen_kwargs)

    def build_ssh_remote_cmd(self, server, opts='', remote_cmd=''):
        """Create a command to run a command remotely on a chosen server"""

        opts = opts or ' '.join(self.ssh_opts())
        return "ssh {opts} {server} {remote_cmd}".format(
                    opts=opts,
                    server=server,
                    remote_cmd=remote_cmd)

    def build_tunnel_cmd(self, lport, rport, server, remote_ip='127.0.0.1',
                       remote_cmd=''):
        """Command to open a tunnel and start a remote process"""

        opts = self.ssh_opts()
        opts.append(
            '-L {lport}:{remote_ip}:{rport}'.format(
                lport=lport,
                rport=rport,
                remote_ip=remote_ip
            )
        )
        return self.build_ssh_remote_cmd(server, opts=' '.join(opts),
                                       remote_cmd=remote_cmd)

    def build_remote_copy_cmd(self, server, resource_path, target_dir=''):
        """Command to copy a directory to a remote target directory"""

        opts = self.ssh_opts()
        cmd = "scp {opts} -r {cp_dir}/ {server}:{target}/"
        cmd = cmd.format(opts=' '.join(opts), cp_dir=resource_path,
                         server=server, target=target_dir)
        return cmd

    def env_cmd(self, host=None):
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

        remote_env = None
        if host:
            cmd = self.build_ssh_remote_cmd(host, remote_cmd="/bin/env")
            proc = self.exec_as_spawning_user(shlex.split(cmd))

            try:
                out, err = proc.communicate(timeout=15)
                if err:
                    self.log.warn(err.decode().strip())
                if out:
                    remote_env = env_str_to_dict(out.decode())
            except TimeoutExpired:
                self.log.warn("Timed out trying to get {user}'s environment"
                              .format(user=self.user.name))
                proc.kill()

        env = self.get_env(other_env=remote_env)
        cmd = ["/bin/env"]
        cmd = cmd + [pipes.quote("{var}={val}"
                     .format(var=var, val=val)) for var, val in env.items()]
        return cmd

    def get_args(self):
        """Get the args to send to the jupyterhub-singleuser command

        Extends the default `get_args` command and adds arguments for security
        and specifically to make the SSHSpawner work.
        """

        args = super().get_args()
        args.append('--SingleUserNotebookApp.allow_origin_pat={patt}'
            .format(patt='.*\.llnl\.gov'))
        args.append('--MappingKernelManager.cull_idle_timeout={timeout}'
            .format(timeout=self.idle_timeout))

        # TODO This is currently very important as the default tcp protocol
        # has no means of enabling encryption. Need to develop the feature
        # in the Jupyter client to propagate and use certs enabled by
        # `internal_ssl`
        args.append('--KernelManager.transport=ipc')

        if self.local_logfile:
            args.append('2>&1 | tee -a {base}/{logfile}'.format(
                base=self.resource_path, logfile=self.local_logfile))

        return args

    def cmds_to_script(self, filename, cmds):
        """Write the list of commands in cmds to a file specified by filename

        Currently this prepends `#!/bin/bash` to the resulting script and makes
        it executable.
        """

        user = pwd.getpwnam(self.user.name)
        uid = user.pw_uid
        gid = user.pw_gid
        home = user.pw_dir

        template = "#!/bin/bash\n{cmd}"
        outfile = "{home}/{base}/{script}".format(
            home=home,
            base=self.resource_path,
            script=filename
        )

        with open(outfile, 'w') as fh:
            fh.write(template.format(cmd='\n'.join(cmds) + '\n'))

        shutil.chown(outfile, user=uid, group=gid)
        os.chmod(outfile, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        return outfile

    def get_krb_file(self):
        """Find the user's kerberos credential file

        This is later attached to the ssh command to perform passwordless ssh.
        """

        user = pwd.getpwnam(self.user.name)
        uid = user.pw_uid
        if not self._kerberos_filename:
            get_krb_filename_template = ("/bin/ls -tlr /tmp/ "
                                        "| grep 'krb5cc_{user}.*' "
                                        "| tail -1 | awk '{{print $9}}'")
            get_krb_filename = get_krb_filename_template.format(
                user=uid)

            proc = Popen(shlex.split('bash -c') + [get_krb_filename],
                         stdout=PIPE)
            self._kerberos_filename = (proc.stdout.readline().decode().strip()
                                       or '')
        return self._kerberos_filename

    def ips_for_host(self, host):
        """Return all the ips reported by the host command"""

        ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        proc = Popen(['host', host], stdout=PIPE)
        lines = proc.stdout.read().decode().strip().split('\n')

        # Look for ip addresses and build a list of the ones found
        lines = [match.group() for match
                    in [re.search(ip_pattern, line) for line in lines]
                    if match]

        if len(lines) == 0 or re.match('.*not found', lines[0]):
            raise HostNotFound(host)

        return lines

    def get_target_ip(self, host):
        """Return an ip we can connect to from the list of ips gathered from
        the host command."""
        ips = self.ips_for_host(host)
        random.shuffle(ips)
        for ip in ips:
            if can_connect(ip, 22):
                return ip
        raise ConnectionError(host)

    async def start(self):
        """Start the single-user server on a remote host

        Copies all necessary resources over to the target host, starts
        the singleuser server there and opens a tunnel so that the server
        appears as a locally running instance.
        """

        cmd = []
        self.port = random_port()
        args = self.get_args()
        host = pipes.quote(self.user_options['host'])
        self.ssh_target = self.get_target_ip(host)
        env_cmd = self.env_cmd(host=self.ssh_target)
        username = self.user.name
        user = pwd.getpwnam(self.user.name)
        uid = user.pw_uid
        gid = user.pw_gid
        home = user.pw_dir
        home_out_dir = "{home}/{out}".format(
            home=home, out=self.resource_path
        )

        # Command to copy all resources to the remote
        make_remote_resource_dir = self.build_ssh_remote_cmd(
            self.ssh_target,
            remote_cmd="mkdir -p " + self.resource_path
        )

        # TODO: Rely on default home dir
        copy_resources_to_remote = self.build_remote_copy_cmd(
            self.ssh_target,
            home_out_dir,
            target_dir=os.path.dirname(self.resource_path)
        )

        # Build script to start notebook on remote host. This is
        # to keep sensitive info out of ps.
        cmd = env_cmd + self.cmd + args
        self.cmds_to_script(
            self.start_notebook_cmd,
            [' '.join(cmd)]
        )

        # Command to open the tunnel and start the notebook
        tunnel_cmd = self.build_tunnel_cmd(
            self.port,
            self.port,
            self.ssh_target,
            remote_cmd=self.resource_path + '/' + self.start_notebook_cmd
        )

        local_start = self.cmds_to_script(
            'local-start-' + username,
            [
                make_remote_resource_dir,
                copy_resources_to_remote,
                tunnel_cmd,
            ]
        )

        try:
            self.log.info(
                "Spawning notebook for {user} on {host} ({ip}, {port})."
                    .format(user=username, host=host, ip=self.ssh_target,
                            port=self.port)
            )

            # Notebook health will be monitored on the forwarded port, and the
            # tunnel health will be monitored and held as the spawner proc
            self.proc = self.exec_as_spawning_user(
                [local_start], new_session=True)

            # TODO: Pull data from the Notebook log
            out, err = self.proc.communicate(timeout=self.spawn_error_timeout)

            if err:
                stripped_err = err.decode().strip()
                self.log.error(stripped_err)
        except TimeoutExpired:
            pass
        except PermissionError:
            # use which to get abspath
            self.log.error("Permission denied trying to start. "
                           "Does %s have access to %s?" %
                           (self.user.name, local_start))
            raise

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

        username = pipes.quote(self.user.name)
        cmd = self.build_ssh_remote_cmd(self.ssh_target,
                                        remote_cmd=self.notebook_stop_cmd)
        proc = self.exec_as_spawning_user(shlex.split(cmd))

        self.log.info("Stopping user {user}'s notebook at port {port} on host"
                      "{host}".format(user=self.user.name, port=self.port,
                                      host=self.ssh_target))

        out, err = proc.communicate(timeout=15)
        if err:
            self.log.error("Errors encountered while stopping notebook: {}"
                           .format(err.decode().strip()))

        # TODO: Use code to update list of potentially orphaned notebooks
        if proc.returncode == 0:
            self.log.info("Notebook stopped")

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
