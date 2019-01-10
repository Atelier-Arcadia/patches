# Patches

Patches is inspired by a use case for the [Mozilla InvestiGator](https://github.com/mozilla/mig)
project wherein information about vulnerable packages is fed from the [Clair](https://github.com/coreos/clair)
database into MIG Agents.  These agents scan for those vulnerable packages on their respective hosts and report
which ones they find.

## Feature Summary

* Patches is designed to be fully distributed and run on server infrastructure.
* Agents can operate as either scanners or vulnerability knowledge bases.
* Knowledge bases maintain information about vulnerable packages and share it with peers.
* Scanners retain some knowledge about vulnerable packages and scan for them until they are patched.

## Operational Phases

Both types of agents will begin operation by searching for peers.

### Servers

A server will periodically query for new vulnerable package information. Upon learning of new packages, it
will ask peers to scan for them. If a peer does not respond, it will be periodically be pinged again until it responds
or a time threshold is met.

### Scanners

Scanners listen for information about vulnerable packages. Upon receipt of such information, the scanner will search
the host's filesystem for the vulnerable package.  The scanner never reports to its peers whether it finds
vulnerable packages or not- it will only acknowledge that it has performed the scan.  Instead, scanners can be
configured to output their findings to be inspected on the host or ingested by other software.

Scanners will retain information about vulnerable packages they find on their host and periodically check if it is
still present (and reporting it if it is) indefinitely until the package is patched.
