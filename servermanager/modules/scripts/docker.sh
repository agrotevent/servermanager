# shellcheck shell=bash
# Env: SM_TASK, SM_CONTAINER, SM_PROJECT
command -v docker >/dev/null 2>&1 || die "Docker ist nicht installiert"

compose_cmd() {
    if docker compose version >/dev/null 2>&1; then
        docker compose "$@"
    elif command -v docker-compose >/dev/null 2>&1; then
        docker-compose "$@"
    else
        die "Weder 'docker compose' noch 'docker-compose' verfügbar"
    fi
}

project_label() {
    docker ps -a --filter "label=com.docker.compose.project=$1" --format "{{.Label \"$2\"}}" | grep -v '^$' | head -n 1
}

project_args() {
    local p="$1" wd files f
    wd="$(project_label "$p" com.docker.compose.project.working_dir)"
    files="$(project_label "$p" com.docker.compose.project.config_files)"
    [ -n "$wd" ] && [ -d "$wd" ] || { warn "Projekt $p: Arbeitsverzeichnis unbekannt"; return 1; }
    PROJECT_DIR="$wd"
    PROJECT_ARGS=(-p "$p")
    IFS=',' read -r -a fl <<< "$files"
    for f in "${fl[@]}"; do
        [ -f "$f" ] && PROJECT_ARGS+=(-f "$f")
    done
    [ "${#PROJECT_ARGS[@]}" -gt 2 ] || { warn "Projekt $p: Compose-Datei nicht gefunden ($files)"; return 1; }
}

project_update() {
    project_args "$1" || return 1
    log "Projekt $1: Images laden (pull)"
    (cd "$PROJECT_DIR" && compose_cmd "${PROJECT_ARGS[@]}" pull) || { warn "pull fehlgeschlagen"; return 1; }
    log "Projekt $1: Container aktualisieren (up -d)"
    (cd "$PROJECT_DIR" && compose_cmd "${PROJECT_ARGS[@]}" up -d) || { warn "up -d fehlgeschlagen"; return 1; }
}

projects() {
    docker ps -a --format '{{.Label "com.docker.compose.project"}}' | grep -v '^$' | sort -u
}

case "${SM_TASK}" in
    container_start|container_stop|container_restart|container_remove)
        valid_name "${SM_CONTAINER}" || die "Ungültiger Containername"
        verb="${SM_TASK#container_}"
        if [ "$verb" = "remove" ]; then
            log "docker rm -f ${SM_CONTAINER}"
            docker rm -f -- "${SM_CONTAINER}"
        else
            log "docker ${verb} ${SM_CONTAINER}"
            docker "$verb" -- "${SM_CONTAINER}"
        fi
        ;;
    compose_update)
        valid_name "${SM_PROJECT}" || die "Ungültiger Projektname"
        project_update "${SM_PROJECT}" || die "Aktualisierung von ${SM_PROJECT} fehlgeschlagen"
        ;;
    compose_restart)
        valid_name "${SM_PROJECT}" || die "Ungültiger Projektname"
        project_args "${SM_PROJECT}" || die "Projekt nicht gefunden"
        (cd "$PROJECT_DIR" && compose_cmd "${PROJECT_ARGS[@]}" restart)
        ;;
    compose_update_all)
        failed=0
        found=0
        while read -r p; do
            [ -n "$p" ] || continue
            found=1
            project_update "$p" || failed=$((failed + 1))
        done < <(projects)
        [ "$found" = "1" ] || log "Keine Compose-Projekte gefunden."
        [ "$failed" -eq 0 ] || die "$failed Projekt(e) konnten nicht aktualisiert werden"
        ;;
    image_prune)
        log "Ungenutzte Images entfernen (docker image prune -af)"
        docker image prune -af
        ;;
    check_updates)
        log "Prüfe Images laufender Container auf neue Versionen (docker pull)"
        docker ps --format '{{.Names}}|{{.Image}}' | sort -t'|' -k2 | while IFS='|' read -r name image; do
            case "$image" in *@sha256:*|sha256:*) continue ;; esac
            cur="$(docker inspect -f '{{.Image}}' "$name" 2>/dev/null)"
            if docker pull -q "$image" >/dev/null 2>&1; then
                new="$(docker image inspect -f '{{.Id}}' "$image" 2>/dev/null)"
                if [ -n "$new" ] && [ "$cur" != "$new" ]; then
                    echo "update=$name|$image"
                else
                    echo "current=$name|$image"
                fi
            else
                echo "unchecked=$name|$image"
            fi
        done
        ;;
    *) die "Unbekannte Aufgabe ${SM_TASK}" ;;
esac
