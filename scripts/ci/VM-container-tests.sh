#!/bin/bash

set -e

SSH_PORT=2223
# Argument retrieval
# -----------------------------------------------
while [[ $# > 0 ]]; do
  case $1 in
    -h|--help)
      echo -e "Performs set of tests to start, stop and modify containers in VM among other operations."
      echo " "
      echo "Run with ./run-tests.sh [-c] [-k] [-v <display number>] [-f] [-b <branch name>] [-d <directory>]"
      echo " "
      echo "options:"
      echo "-h, --help                  Show brief help"
      echo "-c, --compile               (Re-)compile images (e.g. if new changes were commited to the repository)"
      echo "-b, --branch <branch>       Use this device_fraunhofer_common_cml git branch (if not default) during compilation"
      echo "                            (see cmld recipe and init_ws.sh for details on branch name and repository location)"
      echo "-d, --dir <directory>       Use this path to workspace root directory if not current directory"
      echo "-f, --force                 Clean up all components and rebuild them"
      echo "-s, --ssh <ssh port>        Use this port on the host for port forwarding (if not default 2223)"
      echo "-v, --vnc <display number>  Start the VM with VNC (port 5900 + display number)"
      echo "-t, --telnet <telnet port>  Start VM with telnet on specified port (connect with 'telnet localhost <telnet port>')"
      echo "-k, --kill                  Kill the VM after the tests are completed"
      exit 0
      ;;
    -c|--compile)
      COMPILE=true
      shift
      ;;
    -b|--branch)
      shift
      BRANCH=$1
      if [[ $BRANCH  == "" ]]
      then
        echo "No  branch specified. Run with --help for more information."
        exit 1
      fi
      shift
      ;;
    -d|--dir)
      shift
      if [[ $1  == "" || ! -d $1 ]]
      then
        echo "No (existing) directory specified. Run with --help for more information."
        exit 1
      fi
      cd $1
      shift
      ;;
    -f|--force)
      shift
      FORCE=true
      ;;
    -v|--vnc)
      shift
      if ! [[ $1 =~ ^[0-9]+$ ]]
      then
        echo "Error: VNC port must be a number. (got $1)"
        exit 1
      fi
      VNC="-vnc 0.0.0.0:$1"
      shift
      ;;
    -s|--ssh)
      shift
      SSH_PORT=$1
      if ! [[ $SSH_PORT =~ ^[0-9]+$ ]]
      then
        echo "Error: ssh host port must be a number. (got $SSH_PORT)"
        exit 1
      fi
      shift
      ;;
    -t|--telnet)
      shift
      if ! [[ $1 =~ ^[0-9]+$ ]]
      then
        echo "Error: telnet host port must be a number. (got $1)"
        exit 1
      fi
      TELNET="-serial mon:telnet:127.0.0.1:$1,server,nowait"
      shift
      ;;
    -k|--kill)
      shift
      KILL_VM=true
      ;;
     *)
      echo "Unnecessary arguments? ($1)"
      exit
      ;;
  esac
done

# Compile project
# -----------------------------------------------
if [[ $COMPILE == true ]]
then
	# changes dir to out-yocto/
	source init_ws.sh out-yocto x86 genericx86-64

	if [[ $FORCE == true ]]
	then
		bitbake -c clean multiconfig:container:trustx-core
		bitbake -c clean cmld
		bitbake -c clean trustx-cml-initramfs
		bitbake -c clean trustx-cml
	fi
  if [[ $BRANCH != "" ]]
  then
	  # TODO \${BRANCH} is defined in init_ws.sh -> if changes there, this won't work
	  sed -i "s/branch=\${BRANCH}/branch=$BRANCH/g" cmld_git.bbappend
	fi
  bitbake multiconfig:container:trustx-core
	bitbake trustx-cml
else
	if [ ! -d "out-yocto" ]
	then
		echo "ERROR: Project setup not complete. Try with --compile?"
		exit
	fi
	cd out-yocto
fi

# Check if cmld was build
if [ -z $(ls -d tmp/work/core**/cmld/git**/git) ]
then
  echo "ERROR: No cmld build found: did you compile?"
  exit
fi

# Check if the branch matches the built one
if [[ $BRANCH != "" ]]
then
  BUILD_BRANCH=$(git -C tmp/work/core*/cmld/git*/git branch | grep '*' | awk '{ print $NF }')  # check if git repo found and correct branch used
  if [[ $BRANCH != $BUILD_BRANCH ]]
  then
    echo "ERROR: The specified branch \"$BRANCH\" does not match the build ($BUILD_BRANCH). Please recompile with flag -c."
    exit
  fi
fi

# Create image
# -----------------------------------------------
echo "STATUS: Creating images"
rm -f containers.btrfs
dd if=/dev/zero of=containers.btrfs bs=1M count=10000 &> /dev/null
mkfs.btrfs -L containers containers.btrfs &> /dev/null

# Backup system image
# TODO it could have been modified if VM run outside of this script with different args already
cp tmp/deploy/images/genericx86-64/trustme_image/trustmeimage.img trustmeimage.img

# Start VM
# -----------------------------------------------
echo "STATUS: Starting VM"
PROCESS_NAME="qemu-trustme-t"
if [[ $(pgrep $PROCESS_NAME) != "" ]]
then
  echo "WARNING: VM instance called \"$PROCESS_NAME\" already running. Please stop/kill it first."
  exit
fi

# copy for faster startup
cp /usr/share/OVMF/OVMF_VARS.fd .

qemu-system-x86_64 -machine accel=kvm,vmport=off -m 1024G -smp 4 -cpu host -bios OVMF.fd \
  -name trustme-tester,process=qemu-trustme-t \
  -nodefaults -nographic \
	-device virtio-rng-pci,rng=id -object rng-random,id=id,filename=/dev/urandom \
	-device virtio-scsi-pci,id=scsi -device scsi-hd,drive=hd0 \
	-drive if=none,id=hd0,file=trustmeimage.img,format=raw \
	-device scsi-hd,drive=hd1 \
	-drive if=none,id=hd1,file=containers.btrfs,format=raw \
	-device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::$SSH_PORT-:22 \
	-drive "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd" \
	-drive "if=pflash,format=raw,file=./OVMF_VARS.fd" \
  $VNC \
  $TELNET &
  # -serial mon:stdio -display curses

# Waiting for VM's ssh server to start and get cert
sleep 1
echo "STATUS: Waiting for VM ssh server to start up..."
ssh-keyscan -T 70 -p $SSH_PORT -H localhost  > /dev/null

# Perform tests
# -----------------------------------------------

ssh -o StrictHostKeyChecking=no -p $SSH_PORT root@localhost "cat > /tmp/template" << EOF
name: "test-container"
guest_os: "trustx-coreos"
guestos_version: 1
assign_dev: "c 4:2 rwm"
EOF

scp -o StrictHostKeyChecking=no -P $SSH_PORT test_certificates/ssig_rootca.cert root@localhost:/tmp/

echo "STATUS: Calling control list"
ssh -o StrictHostKeyChecking=no -p $SSH_PORT root@localhost  "/usr/sbin/control list" | grep -v Abort

echo "STATUS: Calling control list_guestos"
ssh -o StrictHostKeyChecking=no -p $SSH_PORT root@localhost  "/usr/sbin/control list_guestos" | grep -v Abort

echo "STATUS: Calling control create"
ssh -o StrictHostKeyChecking=no -p $SSH_PORT root@localhost  "/usr/sbin/control create /tmp/template" | grep -v Abort

echo "STATUS: Calling control change_pin"
ssh -o StrictHostKeyChecking=no -p $SSH_PORT root@localhost  'echo -ne "trustme\npw\npw\n" | /usr/sbin/control change_pin test-container' | grep CONTAINER_CHANGE_PIN_SUCCESSFUL

echo "STATUS: Calling control start"
ssh -o StrictHostKeyChecking=no -p $SSH_PORT root@localhost  "/usr/sbin/control start test-container --key=pw" | grep CONTAINER_START_OK

echo "STATUS: Calling control list"
ssh -o StrictHostKeyChecking=no -p $SSH_PORT root@localhost "/usr/sbin/control list" | grep test-container

echo "STATUS: Calling control config"
ssh -o StrictHostKeyChecking=no -p $SSH_PORT root@localhost "/usr/sbin/control config test-container" | grep test-container

echo "STATUS: Calling control state"
ssh -o StrictHostKeyChecking=no -p $SSH_PORT root@localhost "/usr/sbin/control state test-container" | grep RUNNING
# below has no other way to verify command success
echo "STATUS: Calling control ca_register"
ssh -o StrictHostKeyChecking=no -p $SSH_PORT root@localhost "/usr/sbin/control ca_register /tmp/ssig_rootca.cert" 2>&1 | grep -v Abort

echo "STATUS: Calling control stop"
ssh -o StrictHostKeyChecking=no -p $SSH_PORT root@localhost "/usr/sbin/control stop test-container --key=pw" | grep CONTAINER_STOP_OK

echo "STATUS: Calling control remove"
ssh -o StrictHostKeyChecking=no -p $SSH_PORT root@localhost "/usr/sbin/control remove test-container" 2>&1 | grep -v FATAL

# above command has no proper return value thus we check below if test-container no longer in list
echo "STATUS: Calling control list"
ssh -o StrictHostKeyChecking=no -p $SSH_PORT root@localhost "/usr/sbin/control list" | grep -v test-container

if [[ $KILL_VM == true ]]
then
  echo "Terminating VM"
  pkill $PROCESS_NAME
fi

# Success
# -----------------------------------------------
echo -e "\n\nSUCCESS: All tests passed"

