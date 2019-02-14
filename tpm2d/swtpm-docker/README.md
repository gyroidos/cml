Docker container with a software TPM2.0 emulator. Communicates with the host through a UNIX socket located in /tmp/swtpmqemu/
To build the container run
```
docker build -t swtpm-docker .
```
