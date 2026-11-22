run_scenario analyzer_success 0 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
    install:/candidate start:packrat:/usr/local/bin/packrat analyzer retire-stage
run_scenario analyzer_failure 1 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
    install:/candidate start:packrat:/usr/local/bin/packrat analyzer stop:packrat:/usr/local/bin/packrat \
    install:/backup/packrat start:packrat:/usr/local/bin/packrat allow-existing-drops retire-stage
run_scenario analyzer_watcher_fail 1 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
    install:/candidate start:packrat:/usr/local/bin/packrat stop:packrat:/usr/local/bin/packrat \
    install:/backup/packrat start:packrat:/usr/local/bin/packrat allow-existing-drops retire-stage
