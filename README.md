# RDPbruteforcer

Usage: RDPbruteforcer.py [-h] -I TARGETIP -U USERNAMESFILE [-P PASSWORDSFILE]
                         [-t THREADS] [-d DOMAIN] [-UeP UEP]
                         [-Timeout TIMEOUT]

Simple RDP Bruteforcer

optional arguments:
  -h, --help        show this help message and exit

Required Arguments:
  -I TARGETIP       Target IP Address
  -U USERNAMESFILE  Usernames file
  -P PASSWORDSFILE  Password file
  -t THREADS        Amount of threads
  -d DOMAIN         Domain Default:""
  -UeP UEP          If true test only Username==password Default:False
  -Timeout TIMEOUT  Timeout Time

