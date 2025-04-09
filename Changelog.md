# Changelog

## Unreleased next version

Bug fixes

Other changes


## 0.3.1-rc1

Released 2025-04-09.

No changes compared to 0.3.1-rc1.


## 0.3.1-rc1

Released 2025-04-09.

Bug fixes

Other changes

* Update dependencies
* Drop support for Ubuntu 16.04, 18.04, and Debian 9
* Add support for Ubuntu 24.04 and Debian 12


## 0.3.0-rc1

Released 2024-09-10.

* Added support for pre-validation of a source repository.


## 0.2.1

Released 2022-11-29.

Bug fixes

* Support empty snapshot (#62)
* Increase cleanup-after default to 1 hour (#54)
* Write new notification file only on change (#55)
* Respect --insecure option (#59)


## 0.2.0

Released 2021-12-13.

The code has had a massive overhaul since version 0.1.x. It has been
simplified and has much better test coverage.

Functionality should be compatible to the known requirements for 0.1.x – but
the CLI arguments have also changed. If you are looking to upgrade from 0.1.x
to this version, please make sure that you read the updated README and
test things thoroughly. In case you run into any issues, do not hesitate to
contact us or make an issue in GitHub. 


## 0.1.3

Released 2021-04-29.

New

* Allow a configurable delay before writing the RRDP notification.xml file (#5)
* Use a symlink for the current rsync directory (#2)
* Debian packages (#11)
* Docker file (#9)


