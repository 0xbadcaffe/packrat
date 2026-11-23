# shellcheck shell=bash
export TEST_IO_SAMPLE="$scratch/pressure" TEST_TRACE="$scratch/pressure-trace"
awk() {
    if [[ ${!#} == /proc/pressure/io ]]; then
        command awk "${@:1:$#-1}" "$TEST_IO_SAMPLE"
    else
        command awk "$@"
    fi
}
export -f awk

pressure='full avg10=12.00 avg60=24.99 avg300=40.01 total=1234'
printf '%s\n' 'some avg10=65.00 avg60=60.00 avg300=10.00 total=1234' "$pressure" >"$TEST_IO_SAMPLE"
PACKRAT_BUILD_MAX_IO_FULL_PERCENT=25 bash "$wrapper" --check wlan1 <"$scratch/source.tar"
assert_clean
diff -u <(printf '%s\n' build '--check wlan1 ') "$TEST_TRACE"
: >"$TEST_TRACE"
for invalid_limit in 101 08 0.5 -1; do
    if PACKRAT_BUILD_MAX_IO_FULL_PERCENT=$invalid_limit bash "$wrapper" --deploy wlan1 <"$scratch/source.tar" 2>"$scratch/error"; then exit 1; fi
    grep -Fq 'must be an integer from 0 to 100' "$scratch/error"
done
for blocked in 'full avg10=25.00 avg60=0.01' 'full avg10=5.00 avg60=40.61'; do
    printf '%s\n' "$blocked" >"$TEST_IO_SAMPLE"
    if PACKRAT_BUILD_MAX_IO_FULL_PERCENT=25 bash "$wrapper" --deploy wlan1 <"$scratch/source.tar" 2>"$scratch/error"; then exit 1; fi
    grep -Fq 'Linux I/O pressure before build is' "$scratch/error"
done
printf '%s\n' 'full avg10=invalid avg60=5.00' >"$TEST_IO_SAMPLE"
if PACKRAT_BUILD_MAX_IO_FULL_PERCENT=25 bash "$wrapper" --deploy wlan1 <"$scratch/source.tar" 2>"$scratch/error"; then exit 1; fi
grep -Fq 'Cannot verify Linux I/O pressure before build' "$scratch/error"
[[ ! -s $TEST_TRACE ]]
assert_clean

printf '%s\n' "$pressure" >"$TEST_IO_SAMPLE"
if TEST_IO_DURING_BUILD='full avg10=0.00 avg60=50.07' PACKRAT_BUILD_MAX_IO_FULL_PERCENT=25 \
    bash "$wrapper" --deploy wlan1 <"$scratch/source.tar" 2>"$scratch/error"; then exit 1; fi
grep -Fq 'Linux I/O pressure after build is 50.07% (limit 25%); capture unchanged.' "$scratch/error"
diff -u <(printf '%s\n' build) "$TEST_TRACE"
assert_clean
