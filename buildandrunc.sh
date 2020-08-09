#!/bin/bash

# set a name for this build
uuid="replace" #$(uuidgen)

# create a build dir to put the program into (silence output, if the dir already exist, fine)
mkdir build > /dev/null 2>&1

# - compile c-files into program:
# find all the files in the current directory with extension "c",
# and pass them to the gcc command. Set as output the first argument
# given to this script

find . -type f \( -name "*.c" ! -name "._*" \) -exec gcc -o build/$uuid '{}' +

# run the program with a path to executable to run in a separate child process
./build/$uuid "/path/to/executable"
