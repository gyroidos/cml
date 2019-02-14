mkdir -p /tmp/swtpmqemu
docker run \
 -td \
 -v /tmp/swtpmqemu/:/opt/swtpmqemu/ \
 swtpm-docker \
 swtpm socket --tpmstate dir=/opt/swtpmqemu --tpm2 --ctrl type=unixio,path=/opt/swtpmqemu/swtpm-sock
