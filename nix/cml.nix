{
  lib,
  stdenv,
  protobuf,
  protobufc,
  protobuf-c-text,
  openssl,
  systemd,
  ibmtss,
  glibc,
}:

let
  protobufcStatic = protobufc.overrideAttrs (_: {
    dontDisableStatic = true;
  });
in
stdenv.mkDerivation {
  pname = "cml";
  version = "1.1";

  src = ../.;

  postPatch = ''
    substituteInPlace daemon/unit.c \
      --replace-fail \
        'static char *unit_bin_path[] = { "/usr/sbin"' \
        "static char *unit_bin_path[] = { \"$out/sbin\", \"$out/bin\", \"/usr/sbin\""
    substituteInPlace daemon/c_vol.c \
      --replace-fail \
        '"/sbin/cml-service-container-static"' \
        "\"$out/bin/cml-service-container-static\""
  '';

  nativeBuildInputs = [
    protobuf
    protobufcStatic
  ];

  buildInputs = [
    protobufcStatic
    protobuf-c-text
    openssl
    systemd
    ibmtss
  ];

  buildPhase = ''
    runHook preBuild

    make -C control -f Makefile_lsb
    make -C daemon -f Makefile_lsb SYSTEMD=y
    make -C scd -f Makefile_lsb
    (
      export NIX_LDFLAGS="$NIX_LDFLAGS -L${glibc.static}/lib -z muldefs"
      make -C service -f Makefile_lsb service-static
    )
    make -C tpm2d -f Makefile_lsb
    make -C tpm2_control -f Makefile_lsb

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    stage="$NIX_BUILD_TOP/stage"
    mkdir -p "$stage" "$out"

    installFlags="PREFIX=$out DESTDIR=$stage"
    make -C control -f Makefile_lsb install $installFlags
    make -C daemon -f Makefile_lsb install $installFlags SYSTEMD=y
    make -C scd -f Makefile_lsb install $installFlags
    (
      export NIX_LDFLAGS="$NIX_LDFLAGS -L${glibc.static}/lib -z muldefs"
      make -C service -f Makefile_lsb service-static install $installFlags
    )
    make -C tpm2d -f Makefile_lsb install $installFlags
    make -C tpm2_control -f Makefile_lsb install $installFlags

    cp -a "$stage/$out/." "$out/"

    runHook postInstall
  '';

  meta = {
    description = "GyroidOS Container Management Layer (CML)";
    homepage = "https://github.com/gyroidos/cml";
    license = lib.licenses.gpl2Only;
    platforms = lib.platforms.linux;
    mainProgram = "cmld";
  };
}
