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
    [[ $* == 'build --locked --release --features real-capture -j 2 --bin packrat --bin packrat-analyze --bin packrat-archive' && $CARGO_INCREMENTAL == 0 ]]
    [[ $PWD == "$HOME/.cache/packrat-native-source."* && -f Cargo.toml && -f Cargo.lock ]]
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
    build build '--deploy wlan1 ') "$TEST_TRACE"
printf '%s\n' 'Packrat native build and rollout tests passed'
