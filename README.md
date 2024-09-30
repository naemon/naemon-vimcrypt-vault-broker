Naemon VIM Vault Broker Module
==============================

This Naemon Eventbroker (NEB) module reads `$VAULT...$` macros from a vim encrypted
file.

Installation
============

When using the OBS repository from https://build.opensuse.org/project/show/home:naemon you can simply
use yum or apt to install this module. Otherwise build it from source.

```bash
  #> yum install naemon-vimvault
  or
  #> apt-get install naemon-vimvault
```

Requirements
------------

  - naemon-devel (at least version 1.2.5)
  - openssl-devel

Building
--------

```bash
  %> ./autogen.sh # optional, run if there is no configure file yet
  %> ./configure
  %> make
```

Usage
=====

Loading the module
------------------

Load the neb module into naemon by adding a new file in `etc/naemon/naemon.d`.

```
broker_module=.../naemon_vimcrypt.so vault=etc/naemon/vault.cfg
```

Module arguments are:

  - `vault`: sets path to vim crypted file.
  - `password`: sets the master password (not recommended)

Environment variables:

  - `NAEMON_VIM_MASTER_PASSWORD`: set the master password from the environment

Initial Vault Creation
----------------------

Create a new file with vim, set the cryptmethod to blowfish2 (this is the only
supported method) and save with `:X`

```
  %> vim -x -c "set cm=blowfish2" etc/naemon/vault.cfg
  <enter password twice>
  <add at least one comment or macro>
  :wq
```

After the initial creation, the file can simply be edited with `vim <file>` and
vim will automatically ask for the master password.

The vault file must not be empty. The syntax follows the resource.cfg except
macros are named `$VAULTx$`.

etc/naemon/vault.cfg:
```
# comments start with a hash sign
$VAULT1$=test
$VAULT2$=example
$VAULT:EXAMPLE$=not only numbers...
```

Note: unlike the user macros, macro definitions are _not_ limited to numbers. Human readable names can be used as well.

Using with Systemd
------------------
Naemon will ask for the master password upon startup. This does not work with
systemd, so we need to change the unit file, so it can ask for a password and
put that into a environment variable:

Edit the systemd unit file:
```
  #> systemctl edit naemon
```

Add this to make systemd ask for a password:
```
[Service]
ExecStartPre=/usr/bin/bash -c "/usr/bin/systemctl set-environment NAEMON_VIM_MASTER_PASSWORD=$(systemd-ask-password 'Naemon Vault Master Password:')"
ExecStartPost=/usr/bin/bash -c "/usr/bin/systemctl unset-environment NAEMON_VIM_MASTER_PASSWORD"
```

Using the macros
----------------
Vault macros can then be used like the user macros (`$USER1$`), ex.:

> [!IMPORTANT]  
> To avoid leakage of sensitive data, it is important to pass values from the vault macros as environment variables. 
> This is also supported by the [mod-gearman-worker-go](https://github.com/ConSol-Monitoring/mod-gearman-worker-go) implementation.
> 
> Make sure to wrap the value macro in single quotes! Otherwise, Naemon might fork an extra shell, which would leak your sensitive information to `ps`.

```
define command {
    command_name    check_http
    command_line    SECURE_PASSWORD='$VAULT$' $USER1$/check_database -u naemon ...
}
```
Unfortunately, most plugins do not support reading credentials from the environment and require specific patching.


> [!CAUTION]
> By passing a vault macro as a parameter, the value of the macro will be visible in `ps`.
> This is a potentially unsafe example.

```
define command {
    command_name    check_http
    command_line    $USER1$/check_http -a "$VAULT1$" "$VAULT:EXAMPLE$" ...
}
```
