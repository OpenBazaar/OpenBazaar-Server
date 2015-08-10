#!/bin/bash

if command -v pylint; then
    PYLINT=pylint
elif command -v pylint2; then
    PYLINT=pylint2
else
    echo 'ERROR: pylint not installed.'
    exit 1
fi

echo '.: Checking python source files...'
errored=0;
count=0;
for file in $(find . -name "*.py" \
    -not -path "./env/*" \
    -not -path "./html/bower_components/*"); do
    if ! $PYLINT --rcfile .pylintrc $file; then
        errored=$((errored + 1));
    fi
    count=$((count + 1));
done

if (( errored > 0 )); then
    echo "FAIL: Detected $errored files with errors."
    exit 1
fi
echo "PASS: Successfully checked $count files."
