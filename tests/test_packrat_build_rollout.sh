#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
wrapper="$root/scripts/packrat-build-rollout.sh"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
export HOME="$scratch/home" CARGO_TARGET_DIR="$scratch/shared/target"
export PACKRAT_BUILD_ROLLOUT="$scratch/rollout" PACKRAT_BUILD_JOBS=2 TEST_TRACE="$scratch/trace"
mkdir -p -- "$HOME/.cache" "$scratch/source"
touch -- "$scratch/source/Cargo.toml" "$scratch/source/Cargo.lock"
tar -cf "$scratch/source.tar" -C "$scratch/source" Cargo.toml Cargo.lock
touch -- "$HOME/.cache/alert-evidence"

cargo() {
    local options='build --locked --release --features real-capture -j 2'
    [[ $CARGO_INCREMENTAL == 0 ]]
    [[ $PWD == "$HOME/.cache/packrat-native-source."* && -f Cargo.toml && -f Cargo.lock ]]
    if [[ ${TEST_ARCHIVE_ONLY:-0} == 1 ]]; then
        [[ $* == "$options --bin packrat-archive" ]]
        printf '%s\n' build-archive >>"$TEST_TRACE"
        mkdir -p -- "$CARGO_TARGET_DIR/release"
        printf '%s\n' archive >"$CARGO_TARGET_DIR/release/packrat-archive"
        return
    fi
    [[ $* == "$options --bin packrat --bin packrat-analyze --bin packrat-archive" ]]
    printf '%s\n' build >>"$TEST_TRACE"
    [[ ${TEST_BUILD_FAIL:-0} != 1 ]] || return 37
    mkdir -p -- "$CARGO_TARGET_DIR/release"
    printf '%s\n' capture >"$CARGO_TARGET_DIR/release/packrat"
    printf '%s\n' analyzer >"$CARGO_TARGET_DIR/release/packrat-analyze"
    printf '%s\n' archive >"$CARGO_TARGET_DIR/release/packrat-archive"
}
export -f cargo

df() {
    [[ $# == 4 && $1 == -k && $2 == --output=avail && $3 == -- ]]
    printf '%s\n' 'Avail'
    case ${TEST_DISK_FAIL:-}:$4 in
        "low:$HOME/.cache") printf '%s\n' 2097151 ;;
        "invalid:$CARGO_TARGET_DIR") printf '%s\n' unknown ;;
        *) printf '%s\n' 2097152 ;;
    esac
}
export -f df

# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
    'if [[ ${TEST_ARCHIVE_ONLY:-0} == 1 ]]; then' \
    '  [[ $# == 4 && $2 == /usr/local/bin/packrat && $4 == --companions-only && -z $PACKRAT_ROLLOUT_ANALYZER ]]' \
    '  [[ $PACKRAT_ROLLOUT_ARCHIVE == "$HOME/.cache/packrat-native-source."*/packrat-archive && -x $PACKRAT_ROLLOUT_ARCHIVE ]]' \
    '  [[ ! -e ${PACKRAT_ROLLOUT_ARCHIVE%/*}/packrat && ! -e ${PACKRAT_ROLLOUT_ARCHIVE%/*}/packrat-analyze ]]' \
    '  [[ $(<"$PACKRAT_ROLLOUT_ARCHIVE") == archive ]]' \
    '  printf "%s\n" "$1 $3 $4" >>"$TEST_TRACE"' \
    '  exit "${TEST_ROLLOUT_STATUS:-0}"' \
    'fi' \
    '[[ $2 == "$HOME/.cache/packrat-native-source."*/packrat && $PACKRAT_ROLLOUT_ANALYZER == "${2%/*}/packrat-analyze" ]]' \
    '[[ -x $2 && -x $PACKRAT_ROLLOUT_ANALYZER && $(<"$2") == capture && $(<"$PACKRAT_ROLLOUT_ANALYZER") == analyzer ]]' \
    '[[ $PACKRAT_ROLLOUT_ARCHIVE == "${2%/*}/packrat-archive" && -x $PACKRAT_ROLLOUT_ARCHIVE && $(<"$PACKRAT_ROLLOUT_ARCHIVE") == archive ]]' \
    'printf "%s\n" "$1 $3 ${4-}" >>"$TEST_TRACE"' \
    'exit "${TEST_ROLLOUT_STATUS:-0}"' >"$PACKRAT_BUILD_ROLLOUT"
chmod +x -- "$PACKRAT_BUILD_ROLLOUT"

shopt -s nullglob
assert_clean() {
    local -a stages=("$HOME/.cache"/packrat-native-source.*)
    [[ ${#stages[@]} == 0 && -f $HOME/.cache/alert-evidence ]]
}
bash "$wrapper" --check wlan1 <"$scratch/source.tar"
assert_clean
bash "$wrapper" --deploy wlan1 --enable-alert-evidence <"$scratch/source.tar"
assert_clean
for mode in --check --deploy; do
    TEST_ARCHIVE_ONLY=1 PACKRAT_ROLLOUT_ANALYZER=/not-a-candidate \
        bash "$wrapper" "$mode" wlan1 --archive-only <"$scratch/source.tar"
    assert_clean
done
if bash "$wrapper" --deploy wlan1 --archive-only --enable-alert-evidence <"$scratch/source.tar" 2>/dev/null; then exit 1; fi
status=0
TEST_BUILD_FAIL=1 bash "$wrapper" --deploy wlan1 <"$scratch/source.tar" || status=$?
[[ $status == 37 ]]
assert_clean
status=0
TEST_ROLLOUT_STATUS=32 bash "$wrapper" --deploy wlan1 <"$scratch/source.tar" || status=$?
[[ $status == 32 ]]
assert_clean
if bash "$wrapper" --deploy wlan1 </dev/null 2>/dev/null; then exit 1; fi
assert_clean
for disk_failure in low invalid; do
    if TEST_DISK_FAIL=$disk_failure bash "$wrapper" --deploy wlan1 <"$scratch/source.tar" 2>"$scratch/error"; then exit 1; fi
    grep -Fq 'Cannot verify 2048 MiB free' "$scratch/error"
    assert_clean
done
if PACKRAT_BUILD_MIN_FREE_MIB=2049 bash "$wrapper" --deploy wlan1 <"$scratch/source.tar" 2>/dev/null; then exit 1; fi
assert_clean
(
    flock -n 8
    if bash "$wrapper" --deploy wlan1 <"$scratch/source.tar" 2>/dev/null; then exit 1; fi
) 8>"$HOME/.cache/packrat-native-build.lock"
assert_clean
diff -u <(printf '%s\n' build '--check wlan1 ' build '--deploy wlan1 --enable-alert-evidence' \
    build-archive '--check wlan1 --companions-only' build-archive '--deploy wlan1 --companions-only' \
    build build '--deploy wlan1 ') "$TEST_TRACE"
printf '%s\n' 'Packrat native build and rollout tests passed'
