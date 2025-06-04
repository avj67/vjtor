#!/bin/bash
set -e # This script runs the Python script with the specified arguments

exec pipenv run python -m app.main "$@"