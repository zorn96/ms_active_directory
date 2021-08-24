#!/bin/bash

set -e

echo "removing legacy artifacts"
rm -rf dist/*
rm -rf ms_active_directory.egg-info

echo "building package"
python setup.py sdist

echo "Done building package"
echo "Please run 'twine upload dist/*' and input pypi credentials to complete release upload, then go to github to tag release and create it"
