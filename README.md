# restic-plus

A python wrapper that adds functionality to restic.

Added functions:

1) Source arguments from a configuration file.
2) Enable a "max-size" configuration setting, that will use the dry-run feature of restic to estimate the target repository storage size before uploading any data.  This is useful for a target storage system that does not allow setting a quota, and you wish to prevent accidental cost runaway. (Wasabi in partcular). 


# Setup

Copy restic-plus.conf.sample to ~/.config/restic-plus/restic-plus.conf and adjust the settings. 

restic must be installed and on the execution path.



