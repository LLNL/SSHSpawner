# SSH Spawner

Extends the JupyterHub LocalProcessSpawner to instead launch notebooks on
a remote host (e.g. a login node).

## Overview

The basic premise of the SSHSpawner is that it performs the normal Jupyter
Notebook start on a remote host of choice. To make the remote notebook appear
as a local one to Jupyter (and avoid opening several high number ports on
_all_ remote hosts), an ssh tunnel is started that directs the remote notebook
port to localhost on the same port on the JupyterHub server.

In general the spawner:

1. Looks up credentials (kerberos, certificates) to attach to operations that
require them (like ssh)
2. Asks the user for the host they want to spawn on
3. Checks connectivity to the host
4. Creates a folder of resources to move to the remote host:
   * All the certs for encrypting communication between the hub and notebook
   * The script used to start a notebook--this is basically the standard
   command JupyterHub uses to start a notebook, but put into a script to avoid
   OAuth credentials from showing up in `ps`
5. Attaches credentials, moves resources to the remote host, and invokes the
`start-notebook` command.
6. Polls the notebook using a single http request on an interval.

## Use

To enable the spawner, import this class in the jupyterhub\_config.py file
and set the spawner class to SSHSpawner:

```python
from sshspawner import SSHSpawner
c.JupyterHub.spawner_class = SSHSpawner
```

## License

LLNL-CODE-771750
