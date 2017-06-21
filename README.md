KEMP API Python SDK
====================
This is a powershell wrapper around the KEMP RESTful API. It is considered a "release candidate." This means that the team behind its engineering has a have a high level of assurance in its quality but would prefer to obtain feedback from the user community before releasing it as an official replacement for our current powershell wrapper.


Installation 
============

* Download the KEMP PowerShell module from this repository by checking the [releases](releases) section

* Install the module in a folder available in PSModulePath ($Env:PSModulePath). If PSModulePath does not contain the module folder value, add the module path to the in PSModulePath environment variable. The module path can be for the current user only or for all users. Recommended values are:

```
$home\Documents\WindowsPowerShell\Modules for the current User

$Env:ProgramFiles\WindowsPowerShell\Modules for All Users
```

Example. Install the KEMP Powershell module for the current user only

* Save the current value of PSModulePath

```$mpath = [Environment]::GetEnvironmentVariable("PSModulePath")```

* Add the new path to the $mpath variable

```$ mpath += ";$home\Documents\WindowsPowerShell\Modules\Kemp.LoadBalancer.Powershell"```

* Add the paths in $currValue to the PSModulePath value.

```[Environment]::SetEnvironmentVariable("PSModulePath", $currValue)```

Import the module to start using it

```
Import-Module Kemp.LoadBalancer.Powershell

Get-Module Kemp.LoadBalancer.Powershell

ModuleType Version Name ExportedCommands

---------- ------- ---- ----------------

Script 7.2.39.0 Kemp.LoadBalancer.Powershell {Add-BondedInterface, A...
```
* To retrieve the list of the available commands, run the following commands

```Get-Command -Module Kemp.LoadBalancer.Powershell```

Documentation
=====
An interface description can be found in [docs](docs).
The listing of all supported commands can be found in [https://kemptechnologies.github.io/powershell-sdk-vnext/ps-help.html](https://kemptechnologies.github.io/powershell-sdk-vnext/ps-help.html) #TODO


Examples
=====
TODO

Contributions
=============
If you're interested in contributing to this project, please read: 

* If you'd like to contribute but would like help, please open an issue.
* All code contributions require test coverage. If a pull request is lacking tests, it will be closed.
* Docstrings are welcomed. We auto-gen docs into the `gh-pages` branch using [Travis](https://travis-ci.org/KEMPtechnologies/python-kemptech-api). 
* If you're submitting a feature, please clearly explain its use case in your pull request. Our team gets warm and fuzzies every time a contribution is made and explanations help greatly.

Bugs
=====
If you believe you've found a bug please create an issue. We may not get to it right away, but rest assured we've seen it and have it queued up for a response. Seriously, we're watching.

Changelog
=========
TODO

Core Contributors
============

* Fabrizio Carpin (KEMP Technologies)

License
=====
This library is __licensed__ under the Apache 2.0 License. The terms of the license are as follows: 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

