# fb-checker

### Usage

Simple golang program, accounts goes to `check.txt`,  then program will try to do classic method of facebook endpoint, check the cookies, output results in two files `valid.txt` or `invalid.txt` depends on status.
Keep in mind the accounts with 2FA/Checkpoint also going to `valid.txt` since this program validates the login (email|password) from `check.txt`. <br>
#### Separator Settings
Yeah for import (depending for your combo lists) or export(valid/invalid txt files) you can change the separators here:

https://github.com/zile42O/fb-checker/blob/35e503ac37d2fb6c1c5517d3f186d9123820439f/main.go#L22
https://github.com/zile42O/fb-checker/blob/35e503ac37d2fb6c1c5517d3f186d9123820439f/main.go#L23

### Build
```
go build
```
### Run
```
go run main
```
Or (if you did build)
```
./main.exe 
```

## Disclaimer
This repository is for educational purposes, the use of this software is your responsibility.
