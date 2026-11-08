# pecaller (PE frames), sourced by tests/linux_ebpf_test.sh. In the ebpf session, when Wine is installed
# (MSMON_TEST_WINE=0 skips it): a fresh prefix is made by untracked processes, then the probe execs
# `wine cmd /c exit`, so a tracked x64 Wine process makes syscalls; check_pecaller.py looks for PE frames
# once $work/ebpf/wine-ran exists.
pecaller_session() {
    [ "$name" = ebpf ] && command -v wine >/dev/null 2>&1 && [ "${MSMON_TEST_WINE:-1}" != 0 ] || return 0
    # Wine runs as root here: keep its files (HOME, menu entries) inside $work.
    mkdir -p "$work/home"
    pecaller_home=$HOME
    export HOME="$work/home" WINEDLLOVERRIDES="mscoree,mshtml=;winemenubuilder.exe=d"
    { WINEPREFIX=$work/prefix WINEDEBUG=-all timeout 180 wineboot -i; WINEPREFIX=$work/prefix wineserver -w; } \
        >"$work/wineboot.log" 2>&1
    # wineboot writes system32 itself; system.reg only appears when that prefix's wineserver saves.
    if [ ! -d "$work/prefix/drive_c/windows/system32" ]; then
        echo "pecaller: wine prefix not created, skipped"
        export HOME="$pecaller_home"; unset WINEDLLOVERRIDES
        return 0
    fi
    if WINEPREFIX=$work/prefix WINEDEBUG=-all timeout 120 "$scope/probe" --exec wine cmd /c exit >"$work/wine.log" 2>&1; then
        touch "$work/ebpf/wine-ran"
    else
        echo "FAIL ebpf: pecaller: probe --exec wine cmd /c exit failed"; tail -n 20 "$work/wine.log"; fail=1
    fi
    WINEPREFIX=$work/prefix wineserver -w
    export HOME="$pecaller_home"
    unset WINEDLLOVERRIDES
}

pecaller_end() { :; }
