#!/usr/bin/env bash
# deploy.sh — run the kv demo on tailnet hosts (Linux, macOS, Android), one
# replica per host, from this machine. A host is its tailnet name, or
# user@name for ssh. On this machine and on hc machines (hc machine add) a replica runs in
# an hc terminal named kv-demo-<id>, so `hc attach [host/]kv-demo-<id>` shows
# it; elsewhere, such as Termux on Android, under nohup. Replica IDs follow
# the host order.
#
# Usage: examples/kv/deploy.sh <command> [HOST...]
#   up HOST...   build, copy and start; print every replica's page
#   status       is each replica of the last `up` running
#   down         stop them and fetch their logs and result files
#
# Environment:
#   PORT       consensus port (default 9000)
#   HTTP_PORT  HTTP port (default 8080)
#   ARGS       extra kv flags, e.g. ARGS="-time 5m"
set -euo pipefail

repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
out=$repo/out/kv
hostsfile=$out/hosts
dir=kv-demo # under the remote home
port=${PORT:-9000}
http=${HTTP_PORT:-8080}

local_host() { [[ ${1#*@} == "$(hostname)" ]]; }

# on HOST CMD runs CMD in HOST's home.
on() {
    if local_host "$1"; then (cd && sh -c "$2"); else ssh -o BatchMode=yes "$1" "$2"; fi
}

# in_hc is true when HOST is this machine or an hc machine. Its replica then
# runs in an hc terminal, and otherwise under nohup with a pid file.
in_hc() { local_host "$1" || hc machine ls --json | grep -q "\"name\":\"${1#*@}\""; }

# hc_on HOST prints the hc flag that targets HOST.
hc_on() { local_host "$1" || echo "--on ${1#*@}"; }

address() { grep -o '"address":"[^"]*"' | cut -d'"' -f4; }

# platform is the host's GOOS-GOARCH; Android (Termux) has its own GOOS.
platform() {
    local os arch android
    # shellcheck disable=SC2016 # expands on the host
    read -r os arch android <<<"$(on "$1" 'echo $(uname -sm) $([ -e /system/bin/linker64 ] && echo android)')"
    case $arch in
    x86_64) arch=amd64 ;;
    aarch64) arch=arm64 ;;
    esac
    echo "${android:-${os,,}}-$arch"
}

up() {
    (($# > 0)) || { echo "up needs hosts" >&2 && exit 2; }
    [[ ! -s $hostsfile ]] || { echo "a demo is running; run down first" >&2 && exit 1; }
    mkdir -p "$out"
    local hosts=("$@") ips=() names remotes webs h i p cwd addr cmd
    local -A bins=()
    for h in "$@"; do ips+=("$(tailscale ip -4 "${h#*@}")"); done
    names=$(printf "%s," "${@#*@}") && names=${names%,}
    remotes=$(printf "%s:$port," "${ips[@]}") && remotes=${remotes%,}
    webs=$(printf "%s:$http," "${ips[@]}") && webs=${webs%,}
    : >"$hostsfile"
    for i in "${!ips[@]}"; do
        h=${hosts[i]}
        p=$(platform "$h")
        if [[ -z ${bins[$p]:-} ]]; then
            bins[$p]=$out/kv-$p
            CGO_ENABLED=0 GOOS=${p%-*} GOARCH=${p#*-} go build -C "$repo" -o "${bins[$p]}" ./examples/kv
        fi
        on "$h" "mkdir -p $dir && rm -f $dir/result.pb"
        if local_host "$h"; then cp "${bins[$p]}" ~/$dir/kv && cwd=~/$dir; else scp -q "${bins[$p]}" "$h:$dir/kv" && cwd=$dir; fi
        cmd="./kv -self ${ips[i]}:$port -remotes $remotes -http $webs -names $names -output result.pb ${ARGS:-}"
        if in_hc "$h"; then
            # shellcheck disable=SC2046 # hc_on is empty or a flag and its value
            addr=$(hc run --bg --json --no-notify --outlive-parent --name "kv-demo-$((i + 1))" $(hc_on "$h") --cwd "$cwd" "$cmd" | address)
        else
            on "$h" "cd $dir && { nohup $cmd >log 2>&1 </dev/null & echo \$! >pid; }"
            addr="nohup"
        fi
        echo "$h $addr" >>"$hostsfile"
        echo "replica $((i + 1)) on $h ($addr): http://${ips[i]}:$http/"
    done
}

# hosts is the running demo's "host address" lines. Loops read them on fd 3,
# since ssh inside a loop would read the rest of the list from stdin.
hosts() { [[ -s $hostsfile ]] || { echo "no running demo" >&2 && exit 1; }; cat "$hostsfile"; }

# running HOST ADDR is true while the replica runs.
running() {
    if [[ $2 == nohup ]]; then
        on "$1" "kill -0 \$(cat $dir/pid 2>/dev/null) 2>/dev/null"
    else
        hc get "$2" --json 2>/dev/null | grep -q '"state":"live"'
    fi
}

status() {
    local h addr
    while read -r h addr <&3; do
        if running "$h" "$addr"; then echo "$h: running"; else echo "$h: stopped"; fi
    done 3< <(hosts)
}

# stop interrupts the replica, the signal it writes its result file on.
stop() {
    if [[ $2 == nohup ]]; then
        on "$1" "kill -INT \$(cat $dir/pid 2>/dev/null) 2>/dev/null"
    else
        hc keys "$2" ctrl+c >/dev/null 2>&1
    fi
}

# exited is true once the replica has exited, waiting up to 10 s.
exited() {
    local i
    for ((i = 0; i < 50; i++)); do
        running "$1" "$2" || return 0
        sleep 0.2
    done
    return 1
}

# fetch copies the replica's output and result file into a run directory.
fetch() {
    local h=$1 addr=$2 run=$3 f
    if [[ $addr != nohup ]]; then
        hc read "$addr" --lines 1000 >"$run/$h.log" 2>/dev/null && hc rm "$addr" >/dev/null 2>&1
    fi
    for f in log result.pb; do
        [[ $f == log && $addr != nohup ]] && continue
        if local_host "$h"; then cp ~/$dir/$f "$run/$h.$f" 2>/dev/null; else scp -q "$h:$dir/$f" "$run/$h.$f" 2>/dev/null; fi ||
            echo "$h: no $f" >&2
    done
}

down() {
    local run h addr left=0
    run=$out/$(date +%Y%m%d-%H%M%S)
    mkdir -p "$run"
    while read -r h addr <&3; do stop "$h" "$addr" || true; done 3< <(hosts)
    while read -r h addr <&3; do
        if exited "$h" "$addr"; then
            fetch "$h" "$addr" "$run"
        else
            echo "$h: still running, or unreachable" >&2 && left=1
        fi
    done 3< <(hosts)
    echo "results in $run"
    if ((left)); then
        echo "kept the host list; run down again, or remove $hostsfile" >&2 && exit 1
    fi
    rm -f "$hostsfile"
}

case ${1:-} in
up) shift && up "$@" ;;
status) status ;;
down) down ;;
*) sed -n '2,/^set -e/p' "$0" | sed '$d; s/^# \{0,1\}//' && exit 2 ;;
esac
