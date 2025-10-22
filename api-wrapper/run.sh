#!/usr/bin/env bash

clear

if [ ! -d "venv" ]
then
    echo "Virtual environment not found. Run: python3 -m venv venv"
    exit 1
fi

if [ -z "$VIRTUAL_ENV" ]
then
    echo "Virtual environment not activated. Run: . venv/bin/activate"
    exit 1
fi

if [ -f query.log ]
then
    rm query.log
fi

python query.py

