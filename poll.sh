#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}" )"
source ../env/bin/activate
./poll.py 2>&1 >> ../polling.log
