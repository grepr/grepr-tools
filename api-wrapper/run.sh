#!/bin/sh

clear

if [ -f query.log ]
then
    rm query.log
fi

python query.py

echo ""
read -p 'Cat log file <y/n>? ' ANS
if [ "$ANS" = "y" ]
then
    cat query.log
fi
