Naemon VIM Vault Broker Module
==============================

This Naemon Eventbroker (NEB) module reads `$VAULT...$` macros from a vim encrypted
file.

Installation
============

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
  %> vim etc/naemon/vault.cfg
  :set cm=blowfish2
  :X
  <enter password twice>
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
```

Using the macros
----------------

Vault macros can then be used like the user macros, ex.:

```
define command {
    command_name    check_http
    command_line    $USER1$/check_http -a "$VAULT1$" ...
}
```
