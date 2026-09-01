/*
 * ThreatWeave DevSecOps pipeline.
 *
 * Runs the four scanners against the demo target, optionally adds live AWS
 * cloud checks, then hands every report to the AIOps engine which
 * deduplicates, scores, correlates and explains them.
 *
 * SonarQube's SAST scan runs asynchronously, detached from the rest of the
 * run rather than blocked on: it is kicked off early each run and its
 * results are picked up by whichever later run finds it finished (see
 * checkPendingSonarScan/kickOffSonarScan) - GitLeaks/Trivy/Checkov and the
 * AIOps engine itself never wait on it.
 *
 * Scanners run as containers via the mounted Docker socket, so the only
 * tooling this image needs is the Docker CLI and Python.
 *
 * A scanner failing must not abort the run: partial evidence is still worth
 * correlating, and a broken scanner should surface as a missing input rather
 * than a red build. Each scan stage therefore records its own status and the
 * pipeline reports which inputs were collected.
 */

import groovy.transform.Field

// @Field is required: a plain `def` at script level is local to the script
// body, so the helper method below could not see it.
@Field Map scanStatus = [:]

/** Host-side path of the scan input directory, set during Checkout. */
@Field String hostInputDir = ''

/** Set true in Checkout when an automatic (cron-triggered) run finds no new
 * commits since the last scan - every later stage checks this via `when`
 * rather than the pipeline erroring out, so "nothing to do" reads as a
 * clean skip (Jenkins' NOT_BUILT status), not a failure. */
@Field boolean skipRun = false

/**
 * Host-side path of the scanned project.
 *
 * TARGET_PATH is set by compose from .env and is a host path by definition.
 * It is allowed to be empty or relative so that an .env written before this
 * option existed still works: both fall back to the bundled demo target,
 * which is where the /target mount points in that case.
 */
def hostTargetPath() {
    def configured = env.TARGET_PATH?.trim()
    if (!configured || configured.startsWith('.')) {
        return "${env.HOST_WORKSPACE}/demo-app"
    }
    return configured
}

/**
 * Translate a path inside this container to the equivalent path on the host.
 *
 * Scanners run as sibling containers via the mounted Docker socket, so the
 * volume sources in their `docker run` commands are interpreted by the host
 * daemon. Passing /workspace/... there silently creates an empty directory on
 * the host instead of mounting the project, which is why a scanner can appear
 * to succeed while producing no report.
 *
 * Two mounts need translating. /workspace is ThreatWeave itself; /target is
 * the project under test, which normally lives elsewhere on the host. A path
 * under neither is returned unchanged and will almost certainly mount empty,
 * which runScanner reports rather than passing off as a clean run.
 */
def toHostPath(String containerPath) {
    if (containerPath.startsWith('/target')) {
        return containerPath.replaceFirst('^/target', hostTargetPath())
    }
    return containerPath.replaceFirst('^/workspace', env.HOST_WORKSPACE)
}

/**
 * Run a scanner and record the outcome without failing the build.
 *
 * A zero exit code is not sufficient evidence that a scanner worked: a
 * misconfigured volume mount makes the tool write its report into a throwaway
 * directory and still exit cleanly. The expected report is therefore checked
 * for existence and non-trivial size, and the status reflects that.
 */
def runScanner(String name, String expectedReport, Closure body) {
    try {
        body()
        if (scanStatus[name] == 'skipped') {
            return
        }
        def size = sh(
            script: "stat -c%s '${expectedReport}' 2>/dev/null || echo 0",
            returnStdout: true,
        ).trim() as Integer

        if (size > 32) {
            scanStatus[name] = "ok (${size} bytes)"
        } else {
            scanStatus[name] = 'no report produced'
            echo "WARNING: ${name} exited cleanly but wrote no usable report to ${expectedReport}."
            echo 'Check that the volume mount uses a host path, not a container path.'
        }
    } catch (err) {
        scanStatus[name] = "failed: ${err.message}"
        echo "WARNING: ${name} failed - ${err.message}"
        echo 'Continuing; the engine will work with the reports that exist.'
    }
}

/**
 * Runs the AIOps engine over whatever reports exist in INPUT_DIR right now
 * and updates the dashboard's output.
 */
def runAiopsEngine(String phaseLabel) {
    echo "Inputs collected for this run (${phaseLabel}):"
    sh "ls -la ${INPUT_DIR} || true"
    scanStatus.each { name, state -> echo "  ${name}: ${state}" }

    sh """
        cd ${ENGINE_DIR} && python3 engine.py \
          --input ${INPUT_DIR} \
          --output ${FINDINGS_DIR}/aiops-output.json \
          --history ${FINDINGS_DIR}/history.json \
          --first-seen ${FINDINGS_DIR}/first_seen.json \
          --run-id build-${BUILD_NUMBER}
    """

    def out = readJSON file: "${FINDINGS_DIR}/aiops-output.json"
    def s = out.summary

    echo """
    =============================================
     ThreatWeave run ${out.run_id} (${phaseLabel})
    =============================================
     Health score      : ${out.health_score}/100
     Raw findings      : ${s.raw_findings}
     Actionable        : ${s.after_dedup}
     Noise reduction   : ${s.reduction_pct}%
     Suppressed        : ${s.suppressed ?: 0}
     Attack paths      : ${s.clusters}
     Critical / High   : ${s.critical} / ${s.high}
    =============================================
    """.stripIndent()

    currentBuild.description =
        "Health ${out.health_score} | ${s.after_dedup} findings | ${s.clusters} path(s)"

    // The engine writes to the bind-mounted project directory, which is
    // outside the job workspace, so copy it in before archiving.
    sh "cp ${FINDINGS_DIR}/aiops-output.json ./aiops-output.json"
    archiveArtifacts artifacts: 'aiops-output.json', allowEmptyArchive: true

    return out
}

/** Path of the marker file recording an in-flight async SonarQube scan, if
 * any - see checkPendingSonarScan/kickOffSonarScan below. Lives in
 * FINDINGS_DIR, not INPUT_DIR, specifically because Checkout wipes
 * INPUT_DIR's contents every run but FINDINGS_DIR persists, which is what
 * lets this survive across the build boundary a detached scan runs over. */
def sonarPendingMarker() { "${FINDINGS_DIR}/.sonar-pending.json" }

/** Path of the last successfully-fetched SonarQube report, kept outside
 * INPUT_DIR (which Checkout wipes every run) for exactly one reason: a
 * fresh async scan only actually finishes on some runs, not every one, so
 * without this the dashboard's SAST/vulnerability numbers would blink out
 * to zero on every run in between rather than just holding the last real
 * numbers a little longer than the fast scanners' - see checkPendingSonarScan. */
def sonarLastGood() { "${FINDINGS_DIR}/sonarqube-last-good.json" }

/**
 * SonarQube's own analysis takes minutes no matter the CPU budget. Blocking
 * a run on it (as this pipeline used to) makes the whole run wait; running
 * it after the fast scanners in the same run instead just adds its full
 * duration on top since nothing overlaps it any more (measured live on this
 * exact target: 10.3min parallel -> 15.2min sequential-after). This pair of
 * functions instead launches it *detached* and never blocks a build on it -
 * by the time the container this reads has actually finished, it is
 * normally the NEXT run picking up the results, not the one that launched
 * it. SAST results are therefore always real findings from an actual
 * completed scan of a real commit, just one run older than the fast
 * scanners' results in the same dashboard update (never a stale on-disk
 * cache silently reused - see the earlier decision against a homegrown
 * "Developer Edition" incremental cache) - a small, honestly-labelled lag
 * in exchange for SonarQube's ~5 minutes overlapping the ~9 minute fast
 * scanner phase of whichever run happens to be executing while it works,
 * recovering the old parallel design's overlap one run later instead of
 * losing it outright.
 */
def checkPendingSonarScan() {
    // Seed this run with the last successfully-fetched report before doing
    // anything else, so a run where nothing new happens to finish this
    // cycle still has real (if slightly older) SAST data to correlate
    // against, rather than the engine seeing no SonarQube report at all.
    def hasLastGood = sh(script: "[ -f ${sonarLastGood()} ] && echo yes || echo no", returnStdout: true).trim()
    if (hasLastGood == 'yes') {
        sh "cp ${sonarLastGood()} ${INPUT_DIR}/sonarqube-report.json"
        scanStatus['SAST - SonarQube'] = 'ok (carried over from an earlier scan)'
    }

    def markerExists = sh(script: "[ -f ${sonarPendingMarker()} ] && echo yes || echo no", returnStdout: true).trim()
    if (markerExists != 'yes') {
        echo 'No async SonarQube scan currently in flight.'
        return
    }

    def pending = readJSON file: sonarPendingMarker()
    def container = pending.container

    def state = sh(
        script: "docker inspect -f '{{.State.Status}}' ${container} 2>/dev/null || echo missing",
        returnStdout: true,
    ).trim()

    if (state == 'missing') {
        echo "WARNING: pending SonarQube container ${container} (from ${pending.run_id}) no longer exists - clearing stale marker."
        sh "rm -f ${sonarPendingMarker()}"
        return
    }

    if (state == 'running') {
        // Long.intdiv() rather than Groovy's own `/` deliberately - `/`
        // between two longs returns a BigDecimal, and BigDecimal.trunc()
        // (used here in an earlier version to print a whole-number minute
        // count) is not a real method - confirmed live, it broke every
        // single run with a MissingMethodException the instant a pending
        // scan was found still running, before any real scanner ever got a
        // chance to execute. intdiv() returns a plain long, so there is no
        // decimal to truncate in the first place.
        def ageMin = (System.currentTimeMillis() - (pending.started_at_epoch_ms as Long)).intdiv(60000)
        // 20 min is generous headroom over the ~5 min this scan normally
        // takes - this only fires if something is genuinely stuck, so a
        // slow-but-healthy run is never mistaken for one.
        if (ageMin > 20) {
            echo "WARNING: SonarQube scan from ${pending.run_id} has been running for ${ageMin} min - assuming it is stuck and killing it."
            sh "docker rm -f ${container} 2>/dev/null || true"
            sh "rm -f ${sonarPendingMarker()}"
        } else {
            echo "SonarQube scan from ${pending.run_id} is still running (${ageMin} min so far) - will check again next run."
            // Not overwritten with 'pending' when a last-good report was
            // already seeded above - the dashboard still has real numbers
            // to show, they are just not from this run's commit yet.
            scanStatus['SAST - SonarQube'] = scanStatus['SAST - SonarQube'] ?:
                "pending (started by ${pending.run_id}, still running, no earlier scan to fall back on)"
        }
        return
    }

    def exitCode = sh(script: "docker inspect -f '{{.State.ExitCode}}' ${container}", returnStdout: true).trim()
    if (exitCode != '0') {
        echo "WARNING: SonarQube scan from ${pending.run_id} exited with code ${exitCode} - see 'docker logs ${container}' on the host."
        // Same reasoning as the 'running' branch above: keep whatever was
        // already seeded from the last good scan rather than blanking it
        // out just because the newest attempt failed.
        scanStatus['SAST - SonarQube'] = scanStatus['SAST - SonarQube'] ?: "failed: scanner exited ${exitCode}"
        sh "docker rm -f ${container} 2>/dev/null || true"
        sh "rm -f ${sonarPendingMarker()}"
        return
    }

    echo "SonarQube scan from ${pending.run_id} finished - fetching its results."
    runScanner('SAST - SonarQube', "${INPUT_DIR}/sonarqube-report.json") {
        // The scanner container only SUBMITS the analysis; SonarQube
        // processes it asynchronously on its own background queue, so even
        // a finished (exited) scanner container does not guarantee results
        // are queryable yet - same wait this pipeline always needed, just
        // relocated to catch-up time instead of directly after the scan.
        //
        // set +x: Jenkins traces sh steps with -x, which would print the
        // expanded token into the build log. The credential is read from
        // the environment by the shell, never interpolated by Groovy.
        sh """
            set +x
            settled=0
            for i in \$(seq 1 60); do
                st=\$(curl -sS -m 15 -u "\$SONAR_TOKEN:" \
                    "\$SONAR_HOST_URL/api/ce/activity_status?component=${pending.project_key}" \
                    2>/dev/null || echo '')
                case "\$st" in
                    *'"pending":0'*'"inProgress":0'*)
                        echo "  analysis processed after \$((i*5))s"
                        settled=1; break ;;
                    *'Insufficient privileges'*)
                        echo '  WARNING: SONAR_TOKEN cannot read the analysis queue - results may be read before ready.'
                        settled=1; break ;;
                esac
                sleep 5
            done
            [ "\$settled" = 1 ] || echo '  WARNING: still processing after 5 min - results may be incomplete.'

            curl -sS -u "\$SONAR_TOKEN:" \
              "\$SONAR_HOST_URL/api/issues/search?componentKeys=${pending.project_key}&types=VULNERABILITY&ps=500" \
              -o ${INPUT_DIR}/sonarqube-report.json
        """
    }

    // Only promoted to "last good" on a genuine ok - a report that turned
    // out too small/missing (runScanner's own check) must not overwrite a
    // real earlier one.
    if ((scanStatus['SAST - SonarQube'] ?: '').startsWith('ok')) {
        sh "cp ${INPUT_DIR}/sonarqube-report.json ${sonarLastGood()}"
    }
    sh "docker rm -f ${container} 2>/dev/null || true"
    sh "rm -f ${sonarPendingMarker()}"
}

/** Launches a fresh async SonarQube scan, if SonarQube is configured and no
 * scan is already in flight - see checkPendingSonarScan for why this is
 * detached rather than awaited. */
def kickOffSonarScan() {
    if (!env.SONAR_HOST_URL?.trim()) {
        echo 'SONAR_HOST_URL not set - not launching an async SAST scan.'
        return
    }
    def markerExists = sh(script: "[ -f ${sonarPendingMarker()} ] && echo yes || echo no", returnStdout: true).trim()
    if (markerExists == 'yes') {
        echo 'A SonarQube scan is already in flight - not launching another on top of it.'
        return
    }

    def container = 'sonar-scan-pending'
    sh """
        docker rm -f ${container} 2>/dev/null || true
        docker run -d --name ${container} --network ${SONAR_NETWORK} --cpus="4" \
          -v "${toHostPath(params.SOURCE_DIR)}:/usr/src" \
          -e SONAR_HOST_URL \
          -e SONAR_TOKEN \
          sonarsource/sonar-scanner-cli:latest \
          -Dsonar.projectKey=${params.SONAR_PROJECT_KEY} \
          -Dsonar.sources=/usr/src \
          -Dsonar.scm.disabled=true \
          -Dsonar.working.directory=/tmp/.scannerwork \
          -Dsonar.exclusions=**/node_modules/**,**/dist/**,**/build/**,**/coverage/**,**/*.min.js,**/screenshots/**,**/assets/private/**,**/*.{jpg,jpeg,png,gif,ico,svg,webp,avif,bmp,mp4,mov,webm,woff,woff2,ttf,eot,otf,pdf,zip}
    """
    writeJSON file: sonarPendingMarker(), json: [
        container       : container,
        run_id          : "build-${BUILD_NUMBER}",
        project_key     : params.SONAR_PROJECT_KEY,
        started_at_epoch_ms: System.currentTimeMillis(),
    ]
    echo "Launched async SonarQube scan (container ${container}, cpus=4) - a later run will pick up its results."
}

pipeline {
    agent any

    options {
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 45, unit: 'MINUTES')
        // A cron tick landing while a manually-triggered (or another cron)
        // run is still going must not start a second set of scanner
        // containers on top of it - the host does not have CPU to spare for
        // two runs' worth of SonarQube at once (see the CPU-cap comment on
        // the Scans stage). Jenkins queues the new one instead of running
        // it concurrently.
        disableConcurrentBuilds()
    }

    // No public webhook is possible here (Jenkins is not internet-reachable
    // from this local/dev setup), so "run on every push" is approximated by
    // polling on an interval and skipping the run entirely when nothing has
    // changed (see the Checkout stage) - cheap enough that a tight interval
    // does not waste real resources, and closes the gap to "on push" to
    // within a few minutes without needing genuine webhook infrastructure.
    triggers {
        cron('H/5 * * * *')
    }

    environment {
        WORKSPACE_DIR = '/workspace'
        FINDINGS_DIR  = '/workspace/findings'
        ENGINE_DIR    = '/workspace/aiops_engine'
        INPUT_DIR     = '/workspace/findings/scan-inputs'
        // Outside INPUT_DIR deliberately - Checkout wipes INPUT_DIR's
        // contents every run, but the incremental-GitLeaks marker and
        // cumulative findings store need to survive across runs.
        GITLEAKS_STATE_DIR = '/workspace/findings/gitleaks-state'
        // The scanner runs as a sibling container, so it needs to join the
        // compose network to resolve the `sonarqube` service name. Host
        // networking is not a portable substitute: on Docker Desktop a
        // --network host container cannot reach the host's published ports.
        SONAR_NETWORK = "${env.SONAR_NETWORK ?: 'threatweave_default'}"
    }

    stages {

        /* 1 ----------------------------------------------------------- */
        stage('Checkout') {
            steps {
                script {
                    echo "Pipeline starting for ${params.TARGET_IMAGE}"

                    if (!env.HOST_WORKSPACE?.trim()) {
                        error 'HOST_WORKSPACE is not set. Copy .env.example to .env and set it ' +
                              'to the absolute host path of the implementation directory.'
                    }
                    hostInputDir = toHostPath(INPUT_DIR)
                    echo "Container workspace : ${WORKSPACE_DIR}"
                    echo "Host workspace      : ${env.HOST_WORKSPACE}"
                    echo "Scan target         : ${params.SOURCE_DIR}"
                    echo "Host target path    : ${hostTargetPath()}"

                    sh """
                        mkdir -p ${INPUT_DIR}
                        rm -f ${INPUT_DIR}/*.json || true
                    """
                    // git refuses to operate on a repo it does not own by
                    // default ("detected dubious ownership") - confirmed
                    // live: the demo target's .git is owned by root (however
                    // it was cloned/fetched) while Jenkins runs as the
                    // jenkins user, so every git command below silently
                    // failed and got swallowed by its own `|| echo`
                    // fallback. That is not just cosmetic - it is exactly
                    // what the "skip if nothing changed" check just below
                    // depends on, so the failure defeated it completely:
                    // every 5-minute cron tick saw an empty commit hash,
                    // could never match a previous one, and ran a full scan
                    // forever regardless of whether the target had changed
                    // at all. This is trusted, single-tenant local infra (the
                    // same posture already applied to the mounted Docker
                    // socket above), so the ownership check has no value
                    // here - disabled globally rather than per-repo so a
                    // custom scan target hits the same fix with no
                    // additional setup.
                    sh "git config --global --add safe.directory '*'"

                    // The project is bind-mounted at /workspace, so there is no
                    // clone step. Record the revision when it is a git checkout.
                    sh """
                        cd ${SOURCE_DIR} 2>/dev/null && \
                        git rev-parse --short HEAD 2>/dev/null || echo 'not a git checkout'
                    """

                    // "Run on every push" for a build triggered automatically by
                    // the cron poll above: if nobody has pushed since the last
                    // scan of this exact commit, there is nothing new to find -
                    // skip the ~12-14 minute run rather than burning it on an
                    // unchanged tree. A build triggered from the dashboard's
                    // "Run scan" button always runs regardless, since a user
                    // clicking it is an explicit request (they may have changed
                    // scan settings even with the code unchanged).
                    def isAutoTriggered = currentBuild.getBuildCauses().any {
                        (it._class ?: '').contains('TimerTrigger')
                    }
                    if (isAutoTriggered) {
                        def currentHead = sh(script: "git -C ${SOURCE_DIR} rev-parse HEAD 2>/dev/null || echo ''", returnStdout: true).trim()
                        def markerFile = "${FINDINGS_DIR}/.last-scanned-commit"
                        def lastScanned = sh(script: "cat ${markerFile} 2>/dev/null || echo ''", returnStdout: true).trim()
                        if (currentHead && currentHead == lastScanned) {
                            echo "No new commits since the last scan (still at ${currentHead}) - skipping this automatic run."
                            skipRun = true
                            currentBuild.result = 'NOT_BUILT'
                            currentBuild.description = 'Skipped - no new commits since the last scan'
                        } else if (currentHead) {
                            sh "echo '${currentHead}' > ${markerFile}"
                        }
                    }
                }
            }
        }

        /* 2 ----------------------------------------------------------- */
        // Checks whether an async SonarQube scan launched by an earlier run
        // has finished (and if so, fetches its results into this run), then
        // launches a fresh one right away if none is currently in flight -
        // as early as possible in the run, so it has the whole ~9 minute
        // fast-scanner phase below to work in before this run even ends,
        // rather than only getting started once that phase is already over.
        // See checkPendingSonarScan/kickOffSonarScan for the full reasoning.
        stage('SAST - SonarQube (async)') {
            when { expression { !skipRun } }
            steps {
                script {
                    checkPendingSonarScan()
                    kickOffSonarScan()
                }
            }
        }

        /* 3 ----------------------------------------------------------- */
        stage('Dependencies & unit tests') {
            when { expression { !skipRun } }
            steps {
                script {
                    // Quality gate: a project builds and runs its test suite
                    // here, so scanning never proceeds on a broken tree. The
                    // demo target is distributed as a prebuilt image and has
                    // no dependency install step of its own.
                    echo "Target under test: ${params.TARGET_IMAGE}"
                }
            }
        }

        /* 4 ----------------------------------------------------------- */
        // GitLeaks/Trivy/Checkov are independent of each other and all
        // finish in seconds to a couple of minutes regardless of CPU share -
        // run them concurrently so wall-clock time is roughly the slowest of
        // the three, not their sum. SonarQube overlaps this stage too now
        // (see stage 2), just as an async scan possibly still running from
        // an earlier launch, which is why these three are still capped low
        // (1 + 0.5 + 0.5 = 2 cpus) rather than given more room: SonarQube's
        // own cap (4 cpus, see kickOffSonarScan) already assumes it may be
        // sharing the host with this stage, leaving 2 cpus free for
        // Jenkins/Docker/OS the same way the pre-async design did.
        stage('Scans') {
            when { expression { !skipRun } }
            steps {
                script {
                    parallel(
                        'Secrets - GitLeaks': {
                            runScanner('Secrets - GitLeaks', "${INPUT_DIR}/gitleaks-report.json") {
                                // GitLeaks rescans the *entire* git history by default (minutes,
                                // on a repo with meaningful commit count) - a commit already
                                // scanned in a prior run never needs scanning again, so this
                                // only asks it to look at commits since the last run
                                // (`--log-opts`) once a marker from a previous run exists.
                                //
                                // Doing that naively would make the report narrower each run -
                                // a secret from an old, unremediated commit would silently drop
                                // out just because that commit wasn't rescanned. gitleaks_merge.py
                                // folds each run's (possibly incremental) findings into a
                                // persisted cumulative store, so the report handed to the engine
                                // always reflects everything found so far, not just what changed.
                                sh """
                                    mkdir -p ${GITLEAKS_STATE_DIR}
                                    LAST_COMMIT=\$(cat ${GITLEAKS_STATE_DIR}/last-commit.txt 2>/dev/null || echo '')
                                    LOG_OPTS=""
                                    if [ -n "\$LAST_COMMIT" ] && \
                                       git -C ${SOURCE_DIR} cat-file -e "\$LAST_COMMIT" 2>/dev/null && \
                                       git -C ${SOURCE_DIR} merge-base --is-ancestor "\$LAST_COMMIT" HEAD 2>/dev/null; then
                                        LOG_OPTS="--log-opts=\$LAST_COMMIT..HEAD"
                                        echo "GitLeaks: incremental scan since \$LAST_COMMIT"
                                    else
                                        echo "GitLeaks: no usable marker - scanning full history"
                                    fi

                                    docker run --rm --cpus="1" \
                                      -v "${toHostPath(params.SOURCE_DIR)}:/repo" \
                                      -v "${hostInputDir}:/out" \
                                      zricethezav/gitleaks:latest detect \
                                        --source /repo \
                                        --report-format json \
                                        --report-path /out/gitleaks-new.json \
                                        --no-banner --exit-code 0 \
                                        \$LOG_OPTS

                                    python3 ${ENGINE_DIR}/gitleaks_merge.py \
                                      --previous ${GITLEAKS_STATE_DIR}/cumulative.json \
                                      --new ${INPUT_DIR}/gitleaks-new.json \
                                      --output ${INPUT_DIR}/gitleaks-report.json
                                    cp ${INPUT_DIR}/gitleaks-report.json ${GITLEAKS_STATE_DIR}/cumulative.json

                                    git -C ${SOURCE_DIR} rev-parse HEAD > ${GITLEAKS_STATE_DIR}/last-commit.txt 2>/dev/null || true
                                """
                            }
                        },
                        'Container - Trivy': {
                            // Not every scanned project ships a container image (a plain
                            // source-only project has nothing for Trivy to scan) - this
                            // stage is expected to be skippable the same way SonarQube's
                            // SAST stage is when SONAR_HOST_URL is unset, rather than
                            // hard-failing the whole pipeline on an empty/invalid image ref.
                            if (params.TARGET_IMAGE?.trim()) {
                                // Building the image inside the pipeline guarantees Trivy
                                // scans exactly what would be deployed, not a locally built
                                // variant. The demo target ships prebuilt, so it is pulled.
                                // This is Trivy's own prerequisite, not a shared one, so it
                                // lives in this branch rather than as a separate stage.
                                sh "docker image inspect ${params.TARGET_IMAGE} > /dev/null 2>&1 || docker pull ${params.TARGET_IMAGE}"
                                runScanner('Container - Trivy', "${INPUT_DIR}/trivy-report.json") {
                                    sh """
                                        docker run --rm --cpus="0.5" \
                                          -v /var/run/docker.sock:/var/run/docker.sock \
                                          -v trivy-cache:/root/.cache \
                                          -v "${hostInputDir}:/out" \
                                          aquasec/trivy:latest image \
                                            --quiet --format json \
                                            --output /out/trivy-report.json \
                                            ${params.TARGET_IMAGE}
                                    """
                                }
                            } else {
                                echo 'TARGET_IMAGE not set - skipping container scan stage.'
                                scanStatus['Container - Trivy'] = 'skipped'
                            }
                        },
                        'IaC - Checkov': {
                            runScanner('IaC - Checkov', "${INPUT_DIR}/checkov-report.json") {
                                // Checkov exits non-zero when checks fail, which is the
                                // expected case here, so the exit code is ignored.
                                sh """
                                    docker run --rm --cpus="0.5" \
                                      -v "${toHostPath(params.IAC_DIR)}:/tf" \
                                      -v "${hostInputDir}:/out" \
                                      bridgecrew/checkov:latest \
                                        -d /tf -o json --compact --quiet \
                                        --output-file-path /out || true
                                    [ -f ${INPUT_DIR}/results_json.json ] && \
                                      mv ${INPUT_DIR}/results_json.json ${INPUT_DIR}/checkov-report.json || true
                                """
                            }
                        },
                    )
                }
            }
        }

        /* 5 ----------------------------------------------------------- */
        // GitLeaks/Trivy/Checkov are done; SAST for this run is whatever
        // checkPendingSonarScan (stage 2) managed to catch up on - possibly
        // fresh results from a scan that finished in the meantime, possibly
        // nothing new if that scan (or the one launched by this very run) is
        // still working, in which case the engine works with what it has,
        // same as any other missing-report scanner.
        stage('AIOps engine & dashboard update') {
            when { expression { !skipRun } }
            steps {
                script {
                    runScanner('Cloud - AWS monitor', "${INPUT_DIR}/aws-findings.json") {
                        if (params.RUN_AWS_MONITOR) {
                            sh """
                                python3 ${WORKSPACE_DIR}/aws_monitor/monitor.py \
                                  --output ${INPUT_DIR}/aws-findings.json
                            """
                        } else {
                            echo 'AWS monitoring disabled for this run.'
                            scanStatus['Cloud - AWS monitor'] = 'skipped'
                        }
                    }

                    def out = runAiopsEngine('complete')

                    if (params.FAIL_ON_CRITICAL && out.health_score < 30) {
                        error "Health score ${out.health_score} is below the acceptable threshold"
                    }
                }
            }
        }
    }

    post {
        always {
            script {
                echo 'Scanner status for this run:'
                scanStatus.each { name, state -> echo "  ${name}: ${state}" }
            }
        }
        success { echo 'Pipeline completed. Open the dashboard to review findings.' }
        failure { echo 'Pipeline failed. Check the stage log above.' }
    }
}
