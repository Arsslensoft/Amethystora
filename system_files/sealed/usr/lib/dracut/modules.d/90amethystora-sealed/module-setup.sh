#!/usr/bin/bash
# The sealed initramfs's own check (build_files/sealed/00-sealed.sh adds it with bootc's module): the
# system starts only if the composefs root bootc mounted is the signed command line's image, with
# fs-verity required, see amethystora-sealed-verity.

check() {
    return 255
}

depends() {
    echo bootc
}

install() {
    local service=amethystora-sealed-verity.service
    inst_script "${moddir}/amethystora-sealed-verity" /usr/lib/amethystora/amethystora-sealed-verity
    inst_simple "${moddir}/${service}" "${systemdsystemunitdir}/${service}"
    # Required, not wanted: initrd-parse-etc.service, the one way on to switch-root, requires
    # initrd-root-fs.target, which then fails with this check, also when it never started because bootc's
    # root setup failed, or was refused a restart (GHSA-9889-q45r-84v7, which bootc 1.17.5 fixes the same
    # way for its own unit)
    mkdir -p "${initdir}${systemdsystemunitdir}/initrd-root-fs.target.requires"
    ln_r "${systemdsystemunitdir}/${service}" "${systemdsystemunitdir}/initrd-root-fs.target.requires/${service}"
}
