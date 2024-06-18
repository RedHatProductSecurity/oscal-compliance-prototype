#! /bin/bash

. ./sshd-check.config

function check_alive_interval {

    if grep -q "^\s*ClientAliveInterval ${sshd_client_alive_interval}" sshd_config ; then
        echo "pass"
    else
        echo "fail"
    fi
}

function check_alive_count_max {

    if grep -q "^\s*ClientAliveCountMax ${sshd_client_alive_count_max}" sshd_config ; then
        echo "pass"
    else
        echo "fail"
    fi

}


function generate_results() {
    echo "sshd_client_alive_interval=$1" >> sshd-check.results
    echo "sshd_client_alive_count_max=$2" >> sshd-check.results
}

generate_results $(check_alive_interval) $(check_alive_count_max)
