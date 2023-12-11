#!/bin/bash

if  [ "y" = "${CML_DBG}" ];then
	DEBUG="y"
else
	DEBUG="n"
fi

dbg() {
	if [ "y" = "$DEBUG" ];then
		echo "DEBUG: $1" >&2
	fi
}

do_wait_running () {
	echo "STATUS: Wait for container \"$1\" to start (Calling control state)"
	while [ true ];do
		STATE="$(ssh ${SSH_OPTS} "/usr/sbin/control state $1" 2>&1)"

		dbg "STATE: $STATE"

		if ! [ -z "$(grep RUNNING <<< \"${STATE}\")" ];then
			echo "STATUS: Container is running"
			break
		elif ! [ -z "$(grep STARTING <<< \"${STATE}\")" ] || ! [ -z "$(grep BOOTING <<< \"${STATE}\")" ] ;then
			printf "."
			sleep 0.1
		else
			echo "exitcode: $?"
			echo "ERROR: Check failed, expected \"STARTING\" or \"RUNNING\", got:"
			echo "\"${STATE}\""
			exit 1
		fi
	done
}


do_wait_stopped () {
	echo "STATUS: Wait for container \"$1\" to stop (Calling control state)"
	while [ true ];do
		STATE="$(ssh ${SSH_OPTS} "/usr/sbin/control state $1" 2>&1)"

		if ! [ -z "$(grep STOPPED <<< \"${STATE}\")" ];then
			echo "STATUS: Container is stopped"
			break
		else
			printf "."
			sleep 0.5
		fi
	done
}

do_check_params() {
	dbg checking "$1, $2"
	if [[ -z "$1" || -z "$2" ]];then
		echo "ERROR: Required parameters missing"
		exit 1
	fi
}

do_test_cmd_output() {
	do_check_params "$1" "$2"

	echo "STATUS: \"$1\""

	OUTPUT="$(ssh ${SSH_OPTS} "$1" 2>&1)" || true
	dbg "Command returned $OUTPUT, code: $?"

	if echo "$OUTPUT" | grep -q "$2";then
		dbg "exitcode: $?"
		echo "STATUS: Check successful"
		#sleep 2
	else
		echo "exitcode: $?"
		echo "ERROR: Check failed, expected \"$2\", got:"
		echo "\"$OUTPUT\""
		exit 1
	fi
}

do_test_cmd_noutput() {
	do_check_params "$1" "$2"

	echo "STATUS: executing command \"$1\""

	if OUTPUT="$(ssh ${SSH_OPTS} "$1" 2>&1)";then
		echo "STATUS: Command returned $OUTPUT, code: $?"
	fi


	if echo "$OUTPUT" | grep -q "$2";then
		echo "exitcode: $?"
		echo "ERROR: Check failed, did not expect \"$2\", got:"
		echo "\"$OUTPUT\""
		exit 1
	else
		dbg "exitcode: $?"
		echo "STATUS: Check successful"
		#sleep 2
	fi

}



cmd_control_start() {
	do_test_cmd_output "/usr/sbin/control start $1 --key=$2" "CONTAINER_START_OK"
	#sleep 2
	do_wait_running "$1"
	#sleep 2
}

cmd_control_start_error_unpaired() {
	do_test_cmd_output "/usr/sbin/control start $1 --key=$2" "CONTAINER_START_TOKEN_UNPAIRED"
	#sleep 2

}

cmd_control_start_error_eexist() {
	do_test_cmd_output "/usr/sbin/control start $1 --key=$2" "CONTAINER_START_EEXIST"
	#sleep 2
}



cmd_control_stop() {
	do_test_cmd_output "/usr/sbin/control stop $1 --key=$2" "CONTAINER_STOP_OK"
	do_wait_stopped "$1"
	#sleep 2

}

cmd_control_stop_error_notrunning() {
	do_test_cmd_output "/usr/sbin/control stop $1 --key=$2" "CONTAINER_STOP_FAILED_NOT_RUNNING"
	do_wait_stopped "$1"
	#sleep 2

}



cmd_control_list() {
	do_test_cmd_output "/usr/sbin/control list" "code: CONTAINER_STATUS"
}

cmd_control_list_container() {
	do_test_cmd_output "/usr/sbin/control list" "$1"
}

cmd_control_list_ncontainer() {
	do_test_cmd_noutput "/usr/sbin/control list" "$1"
}


cmd_control_list_guestos() {
	do_test_cmd_output "/usr/sbin/control list_guestos" "$1"
}

cmd_control_create() {
if [ -z "$2" ];then
	do_test_cmd_output "/usr/sbin/control create \"$1\"" "guest_os"
else
	do_test_cmd_output "/usr/sbin/control create \"$1\" \"$2\" \"$3\"" "guest_os"
fi

#sleep 5
}

cmd_control_create_error() {
if [ -z "$2" ];then
	do_test_cmd_noutput "/usr/sbin/control create \"$1\"" "uuids"
else
	do_test_cmd_noutput "/usr/sbin/control create \"$1\" \"$2\" \"$3\"" "uuids"
fi

#sleep 5
}


cmd_control_change_pin() {
	do_test_cmd_output "echo -ne \"$2\n$3\n$3\n\" | /usr/sbin/control change_pin $1" "CONTAINER_CHANGE_PIN_SUCCESSFUL"
}

cmd_control_change_pin_error() {
	do_test_cmd_output "echo -ne \"$2\n$3\n$3\n\" | /usr/sbin/control change_pin $1" "CONTAINER_CHANGE_PIN_FAILED"
}



cmd_control_config() {
	do_test_cmd_output "/usr/sbin/control config $1" "$1"
}

cmd_control_remove() {
	do_test_cmd_noutput "/usr/sbin/control remove $1 --key=$2" "Abort"
}

cmd_control_remove_error_eexist() {
	do_test_cmd_output "/usr/sbin/control remove $1 --key=$2" "Container with provided uuid/name does not exist!"
}

cmd_control_ca_register() {
	do_test_cmd_noutput "/usr/sbin/control ca_register $1" "Abort"
}

cmd_control_reboot() {
	do_test_cmd_noutput "/usr/sbin/control reboot" "Abort"
}

cmd_control_get_guestos_version(){
	CMD="/usr/sbin/control list_guestos | grep $1 -A 2 | grep version\: | awk '{print \$2}' | sort | tail -n 1"
	OUTPUT="$(ssh ${SSH_OPTS} "$CMD")"
	echo $OUTPUT
}

cmd_control_retrieve_logs() {
	do_test_cmd_output "/usr/sbin/control retrieve_logs $1" "$2"
}

cmd_control_get_provisioned() {
	do_test_cmd_output "/usr/sbin/control get_provisioned" "device_is_provisioned: $1"
}

cmd_control_set_provisioned() {
	do_test_cmd_output "/usr/sbin/control set_provisioned" "response: $1"
}

cmd_control_list_guestos_silent() {
    OUTPUT="$(ssh ${SSH_OPTS} "/usr/sbin/control list_guestos" 2>&1)" || true
    dbg "Command returned $OUTPUT, code: $?"

    if ! echo "$OUTPUT" | grep -q "$1";then
        dbg "exitcode: $?"
        echo "ERROR: Check failed, expected \"$2\", got:"
        echo "\"$OUTPUT\""
        exit 1
    fi 
}

cmd_control_update_config() {
	do_test_cmd_output "/usr/sbin/control update_config $1" "$2"
}


