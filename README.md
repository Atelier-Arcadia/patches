# patches

Patches scans your endpoints and servers for vulnerable package installations.

Using the [Clair](https://coreos.com/clair/docs/latest/) API as a source of
information about packages with known vulnerabilities, patches periodically
performs a scan on a host for packages containing any vulnerabilities affecting
the host.


⚠️  WARNING ⚠️

While it's extremely unlikely that this software would cause harm to your
computer, it is worth noting that this software is considered to be in _alpha_.

Run at your own risk.

## Architecture

![https://raw.githubusercontent.com/arcrose/patches/master/docs/arch.png](Architecture diagram)

1. The patches-server reads information about vulnerabilities from Clair.
2. The patches-scanner streams that information from the server.
3. The patches-scanner then scans the host it runs on for vulnerable packages.
4. Finally, the patches-scanner reports anything it finds to a reporter API.

## Setup

### Prerequisites

#### Go compiler

First, you must have a working [Go](https://golang.org/) compiler at this time
as packages are not yet being built for patches.  Follow the instructions on
the official site to get a working compiler installed.

#### Debian or Ubuntu host

You will see in the patches-scanner's usage output that it claims to support a
number of different versions of Linux distributions.  At present, patches only
actually includes support for Debian and Ubuntu hosts.  Support for the
remaining hosts will come pretty soon, with any luck, but I'd be happy to help
contributors.

#### Docker

Running a patches-server locally will require running the Clair vulnerability
API and its datbase inside of [Docker](https://www.docker.com/). So you'll
need that installed.

### Running a patches-server

```bash
# Inside the patches/ directory

# 1. Build the server
make server

# 2. Run Clair
docker-compose up -d

# (1) Wait about ten or fifteen minutes for the Clair database to fill up.

# 3. Run the patches server
./patchesserver
```

_Notes:_

(1) - Clair, running in Docker, automatically updates its database with
information about vulnerabilities affecting packages on a variety of
Linux hosts.  This process takes some time but can be checked on manually if
you want to be sure.

```bash
# 1. Get the identifier of the Clair API container.
clairid=`docker ps | grep "clair_clair" | sed "s/ .*//g" | sed "s/ //g"`

# 2. Open a shell instance inside of the Clair API container.
docker exec -it $clairid sh

# 3. Make a request to the Clair API to see if vulnerabilities have been
#    obtained for your platform. If you are running Ubuntu 18.04 for example,
#    look for its name in the output of the following.
#    Note that you may see `{"namespaces": null}` for some time before any
#    data loads.
wget http://127.0.0.1:6060/v1/namespaces; cat namespaces; rm namespaces

# 4. If your platform has data loaded for it, exit.
exit
```

### Running the mock reporter API

The patches-scanner will report any vulnerabilities affecting he host it's
running on to a "reporter API." This API is essentially expected only to
accept requests containing vulnerability information encoded as JSON in the
body and to indicate success with status code 200.

```bash
# 1. Run the reporter API.
go run reportapi.go
```

### Running a patches-scanner

The patches-scanner is the host utility that periodically streams information
about vulnerabilities from a patches-server.  When it finds a vulnerability
affecting an unpatched package on the host, it will report this vulnerability
to a reporter API.

```bash
# 1. Build the scanner.
make scanner

# 2. Run the scanner.
#    This step assumes you have a patches-server and Clair runnig locally.
platform="ubuntu-18.04" # Replace with appropriate platform name for you

./patchesscanner\
	-platform $platform\
	-server-api http://127.0.0.1:8080\
	-vulnerability-api http://127.0.0.1:9001\
	-scan-frequency 1
```

After about one minute, the scanner should start logging information about
requests it's making to the vulnerability server and any findings it produces.

## Contributing

No formal process has been established for this yet.
If you'd like to help out, please feel welcome to open an issue with any
questions.
