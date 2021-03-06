# gluu-snap
SNAP package for GLUU-ce, SNAP package a is new way of 
packaging offering it by Canonical to distribute an app into many different OS into other linux distros.

This package will containg and delivering the same structure as we offer on GLuu-ce rpm's and deb's

If you are interested in testing experimental gluu-snap packages, just jump to [Install gluu-snap Package](#install-gluu-snap-package)

# Building gluu-snap package
**Warning ! This is experimental package.**
Currently gluu-snap package is developed on Ubuntu 18, so you need an Ubuntu 18 machine for both building gluu-snap package and installing/running snap package. 

## Install snapd and snapcraft
The first step is to install snap and snapcraft on your machine:

```
$ sudo apt update
$ sudo apt install snapd
$ sudo apt install snapcraft
```

## Clone repository

```
$ git clone https://github.com/GluuFederation/gluu-snap.git
```

## Building Snap Package

```
$ cd gluu-snap
$ python3 download_apps.py
$ snapcraft
```
This will build snap packaged `gluu-server_<version>_amd64.snap` in current directory. 

# Install gluu-server Snap Package
## Install snapd
Before installing Gluu Server snap package, we need to install snapd. Installing on Ubuntu18 and CentOS7 is quite different:
### Ubuntu 18
To install snap software on Ubuntu you need snapd package installed on your machine. First install **snap** (If you build yourself, you have done this in the prvious step):

```
$ sudo apt update
$ sudo apt install snapd
```
### Debian9/10

```
$ sudo apt update
$ sudo apt install snapd
$ sudo snap install base
$ sudo snap install snapd
```

### CentOS 7

```
$ sudo yum install epel-release
$ sudo yum -y install snapd
$ sudo ln -s /var/lib/snapd/snap /snap
$ sudo systemctl enable --now snapd.socket
```

## Install Gluu Server

If you did not build gluu-server snap package yourself, download latest version of experimental gluu-snap package from https://repo.gluu.org/snaps/
Installing gluu snap package is trivial (please change `<version>` that matches to downloaded package in the following command):

```
$ sudo snap install gluu-server_<version>_amd64.snap --dangerous
```

After installing, you can run setup as follows:

```
$ sudo gluu-server.setup
```

Setup will continue as usual. Please note that you will be asked to install only implemented services.
