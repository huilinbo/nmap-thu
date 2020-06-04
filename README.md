# MultiProcess-Nmap

## What’s MultiProcess-Nmap
A simple script for nmap usage with multiprocess in python.
We use it to nmap a /16 range network to find 68 hosts alive, which costs only 8 min.


## Requirements

python≥3.0 with python-nmap package

## Installation

 pip install python-nmap

## Usage

cd codes

sudo /your/python/path multiProcess.py --host 166.111.0.0/24 --fileName 166log



There're also other options which you can refer to source code file which is rather short. You'd better change other options in source code file, cause I haven't tested them :)



## More

Output is presented in the Json format ,you can refer to python-nmap module usage for more details. I also give two results samples in data directory for your reference .