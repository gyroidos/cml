{
  lib,
  stdenv,
  fetchurl,
  autoreconfHook,
  pkg-config,
  openssl,
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "ibmtss";
  version = "2.5.0";

  src = fetchurl {
    url = "mirror://sourceforge/project/ibmtpm20tss/ibmtss${finalAttrs.version}.tar.gz";
    hash = "sha256-PAZaFhaXLQTozGPUto36KJ4Jd7UhoR/tduWXO8Sa114=";
  };

  sourceRoot = ".";

  outputs = [
    "out"
    "dev"
  ];

  nativeBuildInputs = [
    autoreconfHook
    pkg-config
  ];

  buildInputs = [ openssl ];

  configureFlags = [
    "--enable-tpm-2.0"
    "--disable-tpm-1.2"
    "--enable-hwtpm"
  ];

  enableParallelBuilding = true;

  meta = {
    description = "IBM's TPM 2.0 TSS (user space Trusted Computing software stack)";
    homepage = "https://sourceforge.net/projects/ibmtpm20tss/";
    license = lib.licenses.bsd3;
    platforms = lib.platforms.linux;
  };
})
