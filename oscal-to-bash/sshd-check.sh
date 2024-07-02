#! /bin/bash

. ./sshd-check.config

function check_alive_interval {

    if grep -q "^\s*ClientAliveInterval ${sshd_client_alive_interval}" sshd_config ; then
        echo "pass"
    else
        echo "fail"
    fi
}


function generate_results() {
    echo "sshd_client_alive_interval=$1" >> sshd-check.results
}

generate_results $(check_alive_interval) 
