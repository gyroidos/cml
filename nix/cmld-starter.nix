{ lib, writeShellApplication, cmld }:

let
  mkApp = name: text: {
    type = "app";
    program = lib.getExe (writeShellApplication {
      inherit name text;
    });
  };
in
{
  start-cmld = mkApp "cmld-starter" ''
    if systemctl list-unit-files cmld.socket &>/dev/null; then
      systemctl stop cmld.service cmld.socket
    fi

    systemd-run --unit=cmld --collect \
      --socket-property=FileDescriptorName=cml-control \
      --socket-property=ListenStream=/run/socket/cml-control \
      --socket-property=Accept=no \
      --socket-property=RemoveOnStop=yes \
      ${lib.getExe cmld}
  '';

  stop-cmld = mkApp "cmld-stopper" ''
    systemctl stop cmld.service cmld.socket
  '';
}
