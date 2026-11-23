# shellcheck shell=bash
(
    umask 077
    interface=wlan1
    backup_dir="$scratch/identity-backup"
    installed="$scratch/identity-packrat"
    mkdir -- "$backup_dir"
    printf '%s\n' 'known binary' >"$installed"
    known=$(sha256sum -- "$installed")
    known=${known%% *}
    stamp='{"pid":"42","capture_run_id":"run-a","capture_id":"capture-a","alert_session_id":"session-a"}'
    primary_capture_stamp() {
        if [[ -f $scratch/raced ]]; then jq -c '.capture_id="restarted"' <<<"$stamp"; else printf '%s\n' "$stamp"; fi
    }
    capture_progress_sample() {
        [[ $* == "$main_session $health_addr false" ]] || return 1
        printf '%s\n' "100 ${capture_sample_scope:-run-a:capture-a}"
    }
    alert_watcher_ready() { [[ $1 == "$stamp" && ${watcher_ok:-yes} == yes ]]; }
    sudo() {
        [[ $1 == -n ]] || return 1
        shift
        if [[ $* == 'sha256sum -- /proc/42/exe' ]]; then
            if [[ ${simulate_race:-no} == yes ]]; then touch -- "$scratch/raced"; fi
            printf '%s  /proc/42/exe\n' "${running_hash:-$known}"
        else
            [[ $1 != tee || ${fail_write:-no} != yes ]] || return 1
            command "$@"
        fi
    }
    identify_capture_build | jq -e --arg known "$known" '
        .record_type=="verified_capture_build" and .sha256==$known and .packets==100
        and .interface=="wlan1" and .scope=={capture_id:"capture-a",session_id:"session-a"}' >/dev/null
    if running_hash=0000 identify_capture_build >/dev/null; then exit 1; fi
    if capture_sample_scope=run-b:capture-b identify_capture_build >/dev/null; then exit 1; fi
    if watcher_ok=no identify_capture_build >/dev/null; then exit 1; fi
    if simulate_race=yes identify_capture_build >/dev/null; then exit 1; fi
    rm -- "$scratch/raced"
    if fail_write=yes write_capture_receipt >/dev/null; then exit 1; fi
    [[ -z $(find "$backup_dir" -mindepth 1 -print -quit) ]]
    write_capture_receipt >/dev/null
    jq -e --arg known "$known" '.sha256==$known and .scope.session_id=="session-a"' "$backup_dir/verified-capture.json" >/dev/null
    [[ $(stat -c %a "$backup_dir/verified-capture.json") == 600 ]]
)
