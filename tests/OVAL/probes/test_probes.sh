#!/usr/bin/env bash

# Copyright 2008 Red Hat Inc., Durham, North Carolina.
# All Rights Reserved.
#
# OpenScap Probes Test Suite.
#
# Created on: Nov 30, 2009
#
# Authors:
#      Peter Vrabec, <pvrabec@redhat.com>
#      David Niemoller
#      Ondrej Moris, <omoris@redhat.com>

. ${srcdir}/test_common.sh

# Setup.
function test_probes_setup {
    local ret_val=0

    export OVAL_PROBE_DIR="`pwd`/../src/OVAL/probes/"

    return $ret_val
}

# Test Cases.

function test_probes_import {
    local ret_val=0;
    local TEMPDIR="$(mktemp -d -t -q tmp.XXXXXX)"
    local LOGFILE="test_probes_import.out"
    local EXECDIR="$(pwd)"
    local DEFFILE="${EXECDIR}/OVAL/probes/scap-rhel5-oval.xml"    

    pushd "$TEMPDIR" > /dev/null

    # eval "\"${EXECDIR}/test_probes\" \"--parse\" \"$DEFFILE\" " >> "$LOGFILE"
    # ret_val=$?

    popd > /dev/null

    cp "$TEMPDIR/$LOGFILE" .

    return $ret_val
}

# Check if selected system characteristics were populated correctly. 
function test_probes_system_chars {
    local ret_val=0;
    local LOGFILE="test_probes_system_chars.out"
    local EXECDIR="$(pwd)"
   
    eval "\"${EXECDIR}/test_sysinfo\"" >> "$LOGFILE"

    if [ $? -eq 0 ]; then 
	
	if ! grep -q "os_name: `uname -s`" "$LOGFILE"; then
	    echo "os_name should be `uname -s`" >&2
	    ret_val=$[$ret_val + 1]
	fi
	
	if ! grep -q "os_version: `uname -v`" "$LOGFILE"; then 
	    echo "os_version should be `uname -v`" >&2
	    ret_val=$[$ret_val + 1]
	fi

	if ! grep -q "os_architecture: `uname -i`" "$LOGFILE"; then 
	    echo "os_architecture should be `uname -i`" >&2
	    ret_val=$[$ret_val + 1]
	fi

	if ! grep -q "primary_host_name: `uname -n`" "$LOGFILE"; then 
	    echo "primary_host_name should be `uname -n`" >&2
	    ret_val=$[$ret_val + 1]
	fi

	# FIX ME! (network interfaces check)
	# if [ $ret_val -eq 0 ]; then
	#     for i in `sed -n '6,$p' test_probes_tc02.out | awk '{print $1}'`; do
	# 	IPV4=`ifconfig $i | sed 's/  /\n/g' | grep "inet " | sed 's/addr://' | awk '{print $2}' | sed 's/\/.*$//'`
	# 	IPV6=`ifconfig $i | sed 's/  /\n/g' | grep "inet6 " | sed 's/addr://' | awk '{print $2}' | sed 's/\/.*$//'`
	# 	grep "$IPV4" test_probes_tc02.out | grep -q $i || ret_val=1
	# 	grep "$IPV6" test_probes_tc02.out | grep -q $i || ret_val=1
	#     done
	# fi
	
 	if [ ! $ret_val -eq 0 ]; then
	    echo "" >&2
	    cat "$LOGFILE" >&2
	    echo "" >&2
	    ret_val=2
	fi
    else	
	ret_val=1
    fi

    return $ret_val
}

function test_probes_api {
    local ret_val=0;

    ./test_probe-api > ./test_probes_tc03.out

    ret_val=$?

    return $ret_val
}

function test_probes_file {
    local ret_val=0;
    local LOGFILE="test_probes_file.out"
    local EXECDIR="$(pwd)"
    local DEFFILE="${srcdir}/OVAL/probes/test_probes_file.xml"
    local RESFILE="test_probes_file.xml.results.xml"

    eval "\"${EXECDIR}/test_probes\" \"$DEFFILE\" \"$RESFILE\"" >> "$LOGFILE"

    if [ $? -eq 0 ] && [ -e $RESFILE ]; then

	for ID in `seq 1 15`; do
	    
	    DEF_DEF=`cat "$DEFFILE" | grep "id=\"definition:${ID}\""`
	    DEF_RES=`cat "$RESFILE" | grep "definition_id=\"definition:${ID}\""`

	    if (echo $DEF_RES | grep -q "result=\"true\""); then
		RES="TRUE"
	    elif (echo $DEF_RES | grep -q "result=\"false\""); then
		RES="FALSE"
	    else
		RES="ERROR"
	    fi

	    if (echo $DEF_DEF | grep -q "comment=\"true\""); then
		CMT="TRUE"
	    elif (echo $DEF_DEF | grep -q "comment=\"false\""); then
		CMT="FALSE"
	    else
		CMT="ERROR"
	    fi

	    if [ ! $RES = $CMT ]; then
		echo "Result of definition:${ID} should be ${CMT}!" >&2
		ret_val=$[$ret_val + 1]
	    fi

	done

	for ID in `seq 1 75`; do
	    
	    TEST_DEF=`cat "$DEFFILE" | grep "id=\"test:${ID}\""`
	    TEST_RES=`cat "$RESFILE" | grep "test_id=\"test:${ID}\""`

	    if (echo $TEST_RES | grep -q "result=\"true\""); then
		RES="TRUE"
	    elif (echo $TEST_RES | grep -q "result=\"false\""); then
		RES="FALSE"
	    else
		RES="ERROR"
	    fi

	    if (echo $TEST_DEF | grep -q "comment=\"true\""); then
		CMT="TRUE"
	    elif (echo $TEST_DEF | grep -q "comment=\"false\""); then
		CMT="FALSE"
	    else
		CMT="ERROR"
	    fi

	    if [ ! $RES = $CMT ]; then
		echo "Result of test:${ID} should be ${CMT}!" >&2
		ret_val=$[$ret_val + 1]
	    fi
	    
	done

	if [ ! $ret_val -eq 0 ]; then
	    echo "" >&2
	    cat "$RESFILE" >&2
	    echo "" >&2
	    ret_val=2
	fi

    else 
	ret_val=1
    fi

    [ -e $RESFILE ] && rm -f "$RESFILE"
    
    return $ret_val
}

# Cleanup.
function test_probes_cleanup {     
    local ret_val=0;    

    rm -f "test_probes_*.out"

    return $ret_val
}

# TESTING.

echo ""
echo "--------------------------------------------------"

result=0
log=test_probes.log

exec 2>$log

test_probes_setup   
ret_val=$? 
report_result "test_probes_setup" $ret_val 
result=$[$result+$ret_val]

# test_probes_import 
# ret_val=$? 
# report_result "test_probes_import" $ret_val 
# result=$[$result+$ret_val]   

test_probes_system_chars
ret_val=$? 
report_result "test_probes_system_chars" $ret_val  
result=$[$result+$ret_val]   

# test_probes_api
# ret_val=$?
# report_result "test_probes_api" $ret_val  
# result=$[$result+$ret_val]   

test_probes_file
ret_val=$?
report_result "test_probes_file" $ret_val  
result=$[$result+$ret_val]   

# test_probes_rpminfo
# ret_val=$?
# report_result "test_probes_rpminfo" $ret_val  
# result=$[$result+$ret_val]   

# test_probes_rpminfo
# ret_val=$?
# report_result "test_probes_runlevel" $ret_val  
# result=$[$result+$ret_val]   

# test_probes_textfilecontent
# ret_val=$?
# report_result "test_probes_textfilecontent" $ret_val  
# result=$[$result+$ret_val]   

test_probes_cleanup
ret_val=$?
report_result "test_probes_cleanup" $ret_val 
result=$[$result+$ret_val]

echo "--------------------------------------------------"
echo "See ${log} (in tests dir)"

exit $result


