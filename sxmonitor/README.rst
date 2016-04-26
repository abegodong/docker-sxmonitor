sxmonitor: Nagios monitoring plugins for SX Cluster
===================================================

Introduction
------------

sxmonitor is a suite of Nagios plugins for checking availability of various
resources provided by an SX Cluster. The plugins are written in Python and use
nagiosplugin (https://pypi.python.org/pypi/nagiosplugin) and sxclient
(https://pypi.python.org/pypi/sxclient) packages.


Requirements
------------

In order to work, plugins require Python 2.7 and the following Python packages:

- nagiosplugin >= 1.2.3
- sxclient >= 0.16.4

To install the required packages, run::

   $ pip install nagiosplugin sxclient


Invocation
----------

Run a plugin with the command-line option ``--help`` to display a set of
options available for the plugin. Note that some arguments are mandatory, and
some plugins introduce their own options.
