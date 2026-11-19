{
  lib,
  stdenv,
  fetchFromGitHub,
  autoreconfHook,
  pkg-config,
  re2c,
  check,
  protobufc,
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "protobuf-c-text";
  version = "1.0.0-2023-09-01";

  src = fetchFromGitHub {
    owner = "gyroidos";
    repo = "external_protobuf-c-text";
    rev = "7134d31ec6e7c5feaa33e4fa6cc1eea5dee2e866";
    hash = "sha256-N1/Y13eQnCSYWcXHwulOBCl4iG+C0k7jUfx6mxshp+U=";
  };

  outputs = [
    "out"
    "dev"
  ];

  nativeBuildInputs = [
    autoreconfHook
    pkg-config
    re2c
    protobufc
  ];

  buildInputs = [
    protobufc
    check
  ];

  dontDisableStatic = true;
  configureFlags = [ "--enable-static=yes" ];

  env.NIX_CFLAGS_COMPILE = "-DHAVE_PROTOBUF_C_MESSAGE_CHECK";

  meta = {
    description = "Protobuf text format support for C";
    homepage = "https://github.com/gyroidos/external_protobuf-c-text";
    license = lib.licenses.mit;
    platforms = lib.platforms.unix;
  };
})
