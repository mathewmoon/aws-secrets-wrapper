#!/bin/bash
rm -rf build || echo ""
rm -rf lambda.zip || echo ""
pip3 install --no-cache aws-secrets-wrapper --target build/
cd build

# Get rid of all the garbage. boto3 is provided by the Lambda runtime
# and we don't need any dist-info
rm -rf boto* s3*  *.dist-info|| echo ""
find ./ -name __pycache__ | xargs rm -rf
find ./ -name '*.dist-info' | xargs rm -rf

# This is for TF users who deploy their Lambda by building it on the fly.
# Setting the date on the files prevents drift in the shasum of the package
# unless the actual file contents change
find . -exec touch -t "202401010000.00" '{}' +
zip -0 -X -D -r  ../lambda.zip ./*
cd ..
rm -rf build
