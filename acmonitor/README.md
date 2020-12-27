# Access Control Lib

TO-DO fill this readme...
also util.h is unused but good code

### Brief

This tool overrides the functions `fopen` and `fwrite` to create log entries for file accessing.

It utilizes the `LD_PRELOAD` environment variable.

### Logging

For each file creation, opening and modification, an entry in the logfile is appended and contains :

| Field | Description |
|:-------|--------:|
|  UID  | Unique user ID assigned by the system |
|F​ile name​| Path and name of the accessed file |
|   Date  | The date that the action occurred |
|Timestamp  | The time that the action occurred |
| Access t​ype​  | 0 for creation, 1 for opening, 2 for modifing |
| a​ction-denied flag​  | 1 if the action was denied to the user, or 0 otherwise |
| File fingerprint  | The MD5 hash value of the file contents and timestamp |
