#!/usr/bin/env bash
# Provision and run the SlateFS Azure Blob cross-VM fio harness.
#
# Default action `all` creates a new Azure resource group, storage account,
# one client VM, two daemon VMs, runs the NFS fio matrix against daemon1, collects
# artifacts, and deallocates VMs before exit. Resource groups and storage are
# intentionally left in place for evidence unless AZURE_PRODTEST_DELETE_RG=1.
set -euo pipefail

cd "$(dirname "$0")/.."

ACTION="${1:-all}"

SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:-0a1ca07f-76d3-4739-b946-58d39524082f}"
LOCATION="${AZURE_PRODTEST_LOCATION:-eastus2}"
PREFIX="${AZURE_PRODTEST_PREFIX:-slatefs-prodtest}"
ADMIN_USER="${AZURE_PRODTEST_ADMIN_USER:-azureuser}"
VM_SIZE="${AZURE_PRODTEST_VM_SIZE:-Standard_D4ds_v5}"
CREATE_DAEMON2="${AZURE_PRODTEST_CREATE_DAEMON2:-1}"
DOCKER_PLATFORM="${AZURE_PRODTEST_DOCKER_PLATFORM:-linux/amd64}"
DOCKER_IMAGE="${AZURE_PRODTEST_DOCKER_IMAGE:-rust:1-bullseye}"
CONTAINER="${AZURE_PRODTEST_CONTAINER:-slatefs}"
TENANT="${AZURE_PRODTEST_TENANT:-prodtest}"
VOLUME="${AZURE_PRODTEST_VOLUME:-v1}"
NFS_PORT="${AZURE_PRODTEST_NFS_PORT:-12052}"
METRICS_PORT="${AZURE_PRODTEST_METRICS_PORT:-13052}"
LOCAL_METRICS_PORT="${AZURE_PRODTEST_LOCAL_METRICS_PORT:-13052}"
PROMETHEUS_PORT="${AZURE_PRODTEST_PROMETHEUS_PORT:-9090}"
GRAFANA_PORT="${AZURE_PRODTEST_GRAFANA_PORT:-3000}"
GRAFANA_PASSWORD="${AZURE_PRODTEST_GRAFANA_PASSWORD:-slatefs}"
FIO_RUNTIME="${AZURE_PRODTEST_FIO_RUNTIME:-30}"
FIO_SIZE="${AZURE_PRODTEST_FIO_SIZE:-512m}"
FIO_JOBS="${AZURE_PRODTEST_FIO_JOBS:-4}"
FIO_BS_LIST="${AZURE_PRODTEST_FIO_BS_LIST:-4k 128k 1m}"
FIO_RW_LIST="${AZURE_PRODTEST_FIO_RW_LIST:-read write randread randwrite}"
FIO_PREFILL_BS="${AZURE_PRODTEST_FIO_PREFILL_BS:-4k}"
FIO_PREFILL_FSYNC="${AZURE_PRODTEST_FIO_PREFILL_FSYNC:-0}"
META_OPS="${AZURE_PRODTEST_META_OPS:-500}"
OBSERVABILITY="${AZURE_PRODTEST_OBSERVABILITY:-1}"
DEALLOCATE_VMS="${AZURE_PRODTEST_DEALLOCATE_VMS:-1}"
DELETE_RG="${AZURE_PRODTEST_DELETE_RG:-0}"

RUN_ID=""
RESOURCE_GROUP=""
STORAGE_ACCOUNT=""
VNET=""
SUBNET=""
NSG=""
OBJECT_PREFIX=""
OBJECT_STORE_URL=""
STORAGE_CONNECTION_STRING=""
STORAGE_ACCOUNT_KEY=""
CLIENT_PUBLIC=""
CLIENT_PRIVATE=""
DAEMON1_PUBLIC=""
DAEMON1_PRIVATE=""
DAEMON2_PUBLIC=""
DAEMON2_PRIVATE=""
LOCAL_OUTDIR=""
RIG_ENV="${AZURE_PRODTEST_ENV:-}"
SSH_TUNNEL_PID=""
DEALLOCATE_ON_EXIT=0
SSH_ARGS=()

usage() {
    cat <<EOF
Usage: scripts/azure-prodtest.sh [all|provision|setup|run-fio|observability|collect|deallocate|delete-rg|help]

Environment knobs:
  AZURE_SUBSCRIPTION_ID                 default: $SUBSCRIPTION_ID
  AZURE_PRODTEST_LOCATION               default: $LOCATION
  AZURE_PRODTEST_VM_SIZE                default: $VM_SIZE
  AZURE_PRODTEST_CREATE_DAEMON2         default: $CREATE_DAEMON2
  AZURE_PRODTEST_DOCKER_PLATFORM        default: $DOCKER_PLATFORM
  AZURE_PRODTEST_DOCKER_IMAGE           default: $DOCKER_IMAGE
  AZURE_PRODTEST_ENV                    rig.env for setup/run/deallocate actions
  AZURE_PRODTEST_FIO_RUNTIME            default: $FIO_RUNTIME
  AZURE_PRODTEST_FIO_SIZE               default: $FIO_SIZE
  AZURE_PRODTEST_FIO_JOBS               default: $FIO_JOBS
  AZURE_PRODTEST_GRAFANA_PORT           default: $GRAFANA_PORT
  AZURE_PRODTEST_PROMETHEUS_PORT        default: $PROMETHEUS_PORT
  AZURE_PRODTEST_DEALLOCATE_VMS         default: $DEALLOCATE_VMS
  AZURE_PRODTEST_DELETE_RG              default: $DELETE_RG

The default all action always creates new Azure resources. It saves run state
and secrets under target/azure-prodtest-<run-id>/ and deallocates VMs on exit.
EOF
}

log() {
    printf "== %s\n" "$*"
}

die() {
    printf "ERROR: %s\n" "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"
}

rand_hex() {
    od -An -N2 -tx1 /dev/urandom | tr -d ' \n'
}

shell_quote() {
    printf "%q" "$1"
}

write_env_var() {
    local file="$1"
    local name="$2"
    local value="$3"
    printf "%s=%s\n" "$name" "$(shell_quote "$value")" >> "$file"
}

source_rig_env() {
    local env_file="$1"
    [ -f "$env_file" ] || die "rig env not found: $env_file"
    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
    RUN_ID="${RUN_ID:?missing RUN_ID in $env_file}"
    RESOURCE_GROUP="${RESOURCE_GROUP:?missing RESOURCE_GROUP in $env_file}"
    STORAGE_ACCOUNT="${STORAGE_ACCOUNT:?missing STORAGE_ACCOUNT in $env_file}"
    CONTAINER="${CONTAINER:?missing CONTAINER in $env_file}"
    OBJECT_PREFIX="${OBJECT_PREFIX:?missing OBJECT_PREFIX in $env_file}"
    OBJECT_STORE_URL="${OBJECT_STORE_URL:?missing OBJECT_STORE_URL in $env_file}"
    STORAGE_CONNECTION_STRING="${STORAGE_CONNECTION_STRING:?missing STORAGE_CONNECTION_STRING in $env_file}"
    STORAGE_ACCOUNT_KEY="${STORAGE_ACCOUNT_KEY:?missing STORAGE_ACCOUNT_KEY in $env_file}"
    VNET="${VNET:?missing VNET in $env_file}"
    SUBNET="${SUBNET:?missing SUBNET in $env_file}"
    NSG="${NSG:?missing NSG in $env_file}"
    CLIENT_PUBLIC="${CLIENT_PUBLIC:?missing CLIENT_PUBLIC in $env_file}"
    CLIENT_PRIVATE="${CLIENT_PRIVATE:?missing CLIENT_PRIVATE in $env_file}"
    DAEMON1_PUBLIC="${DAEMON1_PUBLIC:?missing DAEMON1_PUBLIC in $env_file}"
    DAEMON1_PRIVATE="${DAEMON1_PRIVATE:?missing DAEMON1_PRIVATE in $env_file}"
    CREATE_DAEMON2="${CREATE_DAEMON2:-1}"
    if [ "$CREATE_DAEMON2" = "1" ]; then
        DAEMON2_PUBLIC="${DAEMON2_PUBLIC:?missing DAEMON2_PUBLIC in $env_file}"
        DAEMON2_PRIVATE="${DAEMON2_PRIVATE:?missing DAEMON2_PRIVATE in $env_file}"
    else
        DAEMON2_PUBLIC="${DAEMON2_PUBLIC:-}"
        DAEMON2_PRIVATE="${DAEMON2_PRIVATE:-}"
    fi
    LOCAL_OUTDIR="${LOCAL_OUTDIR:?missing LOCAL_OUTDIR in $env_file}"
    TENANT="${TENANT:-prodtest}"
    VOLUME="${VOLUME:-v1}"
    NFS_PORT="${NFS_PORT:-12052}"
    METRICS_PORT="${METRICS_PORT:-13052}"
    RIG_ENV="$env_file"
}

set_ssh_args() {
    SSH_ARGS=(
        -o StrictHostKeyChecking=accept-new
        -o "UserKnownHostsFile=$LOCAL_OUTDIR/known_hosts"
        -o ServerAliveInterval=30
        -o ServerAliveCountMax=6
    )
}

ssh_cmd() {
    local host="$1"
    shift
    set_ssh_args
    # shellcheck disable=SC2029
    ssh "${SSH_ARGS[@]}" "$ADMIN_USER@$host" "$@"
}

scp_to() {
    local src="$1"
    local host="$2"
    local dst="$3"
    set_ssh_args
    scp "${SSH_ARGS[@]}" "$src" "$ADMIN_USER@$host:$dst"
}

scp_from() {
    local host="$1"
    local src="$2"
    local dst="$3"
    set_ssh_args
    scp "${SSH_ARGS[@]}" -r "$ADMIN_USER@$host:$src" "$dst"
}

wait_for_ssh() {
    local host="$1"
    for _ in $(seq 1 90); do
        set_ssh_args
        if ssh "${SSH_ARGS[@]}" -o ConnectTimeout=5 "$ADMIN_USER@$host" true >/dev/null 2>&1; then
            return 0
        fi
        sleep 5
    done
    die "SSH never became ready for $host"
}

cleanup() {
    local status=$?
    set +e
    if [ -n "${SSH_TUNNEL_PID:-}" ]; then
        kill "$SSH_TUNNEL_PID" 2>/dev/null
        wait "$SSH_TUNNEL_PID" 2>/dev/null
    fi
    if [ "$DEALLOCATE_ON_EXIT" = "1" ] && [ "$DEALLOCATE_VMS" = "1" ] && [ -n "${RESOURCE_GROUP:-}" ]; then
        deallocate_vms || true
    fi
    if [ "$DELETE_RG" = "1" ] && [ -n "${RESOURCE_GROUP:-}" ]; then
        delete_resource_group || true
    fi
    exit "$status"
}
trap cleanup EXIT

ensure_azure() {
    require_tool az
    az account set --subscription "$SUBSCRIPTION_ID"
}

current_public_ip() {
    curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true
}

write_rig_env() {
    : > "$RIG_ENV"
    chmod 600 "$RIG_ENV"
    write_env_var "$RIG_ENV" RUN_ID "$RUN_ID"
    write_env_var "$RIG_ENV" SUBSCRIPTION_ID "$SUBSCRIPTION_ID"
    write_env_var "$RIG_ENV" RESOURCE_GROUP "$RESOURCE_GROUP"
    write_env_var "$RIG_ENV" LOCATION "$LOCATION"
    write_env_var "$RIG_ENV" STORAGE_ACCOUNT "$STORAGE_ACCOUNT"
    write_env_var "$RIG_ENV" STORAGE_ACCOUNT_KEY "$STORAGE_ACCOUNT_KEY"
    write_env_var "$RIG_ENV" STORAGE_CONNECTION_STRING "$STORAGE_CONNECTION_STRING"
    write_env_var "$RIG_ENV" CONTAINER "$CONTAINER"
    write_env_var "$RIG_ENV" TENANT "$TENANT"
    write_env_var "$RIG_ENV" VOLUME "$VOLUME"
    write_env_var "$RIG_ENV" NFS_PORT "$NFS_PORT"
    write_env_var "$RIG_ENV" METRICS_PORT "$METRICS_PORT"
    write_env_var "$RIG_ENV" OBJECT_PREFIX "$OBJECT_PREFIX"
    write_env_var "$RIG_ENV" OBJECT_STORE_URL "$OBJECT_STORE_URL"
    write_env_var "$RIG_ENV" VNET "$VNET"
    write_env_var "$RIG_ENV" SUBNET "$SUBNET"
    write_env_var "$RIG_ENV" NSG "$NSG"
    write_env_var "$RIG_ENV" ADMIN_USER "$ADMIN_USER"
    write_env_var "$RIG_ENV" VM_SIZE "$VM_SIZE"
    write_env_var "$RIG_ENV" CREATE_DAEMON2 "$CREATE_DAEMON2"
    write_env_var "$RIG_ENV" DOCKER_PLATFORM "$DOCKER_PLATFORM"
    write_env_var "$RIG_ENV" DOCKER_IMAGE "$DOCKER_IMAGE"
    write_env_var "$RIG_ENV" CLIENT_PUBLIC "$CLIENT_PUBLIC"
    write_env_var "$RIG_ENV" CLIENT_PRIVATE "$CLIENT_PRIVATE"
    write_env_var "$RIG_ENV" DAEMON1_PUBLIC "$DAEMON1_PUBLIC"
    write_env_var "$RIG_ENV" DAEMON1_PRIVATE "$DAEMON1_PRIVATE"
    write_env_var "$RIG_ENV" DAEMON2_PUBLIC "$DAEMON2_PUBLIC"
    write_env_var "$RIG_ENV" DAEMON2_PRIVATE "$DAEMON2_PRIVATE"
    write_env_var "$RIG_ENV" LOCAL_OUTDIR "$LOCAL_OUTDIR"
}

vm_ip() {
    local name="$1"
    local which="$2"
    case "$which" in
        public)
            az vm list-ip-addresses -g "$RESOURCE_GROUP" -n "$name" \
                --query "[0].virtualMachine.network.publicIpAddresses[0].ipAddress" -o tsv
            ;;
        private)
            az vm list-ip-addresses -g "$RESOURCE_GROUP" -n "$name" \
                --query "[0].virtualMachine.network.privateIpAddresses[0]" -o tsv
            ;;
        *) die "unknown ip kind: $which" ;;
    esac
}

create_vm() {
    local name="$1"
    local zone="$2"
    log "creating VM $name ($VM_SIZE, zone $zone)"
    az vm create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$name" \
        --image Ubuntu2204 \
        --size "$VM_SIZE" \
        --admin-username "$ADMIN_USER" \
        --vnet-name "$VNET" \
        --subnet "$SUBNET" \
        --nsg "$NSG" \
        --public-ip-sku Standard \
        --zone "$zone" \
        --generate-ssh-keys \
        -o none
}

provision() {
    ensure_azure
    require_tool curl

    local suffix
    suffix="$(date -u +%m%d%H%M)$(rand_hex)"
    RUN_ID="$(date -u +%Y%m%d%H%M%S)-$(rand_hex)"
    RESOURCE_GROUP="rg-${PREFIX}-${RUN_ID}"
    STORAGE_ACCOUNT="slatefs${suffix}"
    VNET="vnet-${PREFIX}-${RUN_ID}"
    SUBNET="subnet-slatefs"
    NSG="nsg-${PREFIX}-${RUN_ID}"
    OBJECT_PREFIX="prodtest-${RUN_ID}"
    OBJECT_STORE_URL="https://${STORAGE_ACCOUNT}.blob.core.windows.net/${CONTAINER}/${OBJECT_PREFIX}"
    LOCAL_OUTDIR="target/azure-prodtest-${RUN_ID}"
    RIG_ENV="${RIG_ENV:-$LOCAL_OUTDIR/rig.env}"

    mkdir -p "$LOCAL_OUTDIR/artifacts"

    log "creating resource group $RESOURCE_GROUP in $LOCATION"
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION" -o none

    log "creating network"
    az network vnet create \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --name "$VNET" \
        --address-prefixes 10.42.0.0/16 \
        --subnet-name "$SUBNET" \
        --subnet-prefixes 10.42.1.0/24 \
        -o none
    az network nsg create \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --name "$NSG" \
        -o none

    local ssh_source
    ssh_source="${AZURE_PRODTEST_SSH_SOURCE:-$(current_public_ip)}"
    [ -n "$ssh_source" ] && ssh_source="${ssh_source}/32" || ssh_source="*"
    az network nsg rule create \
        --resource-group "$RESOURCE_GROUP" \
        --nsg-name "$NSG" \
        --name allow-ssh \
        --priority 100 \
        --direction Inbound \
        --access Allow \
        --protocol Tcp \
        --source-address-prefixes "$ssh_source" \
        --source-port-ranges '*' \
        --destination-port-ranges 22 \
        -o none

    log "creating storage account $STORAGE_ACCOUNT"
    az storage account create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$STORAGE_ACCOUNT" \
        --location "$LOCATION" \
        --sku Standard_LRS \
        --kind StorageV2 \
        --allow-blob-public-access false \
        --min-tls-version TLS1_2 \
        -o none
    STORAGE_ACCOUNT_KEY="$(az storage account keys list \
        --resource-group "$RESOURCE_GROUP" \
        --account-name "$STORAGE_ACCOUNT" \
        --query '[0].value' -o tsv)"
    STORAGE_CONNECTION_STRING="$(az storage account show-connection-string \
        --resource-group "$RESOURCE_GROUP" \
        --name "$STORAGE_ACCOUNT" \
        --query connectionString -o tsv)"
    az storage container create \
        --name "$CONTAINER" \
        --connection-string "$STORAGE_CONNECTION_STRING" \
        -o none >/dev/null

    create_vm slatefs-client 1
    create_vm slatefs-daemon1 1
    if [ "$CREATE_DAEMON2" = "1" ]; then
        create_vm slatefs-daemon2 2
    fi

    CLIENT_PUBLIC="$(vm_ip slatefs-client public)"
    CLIENT_PRIVATE="$(vm_ip slatefs-client private)"
    DAEMON1_PUBLIC="$(vm_ip slatefs-daemon1 public)"
    DAEMON1_PRIVATE="$(vm_ip slatefs-daemon1 private)"
    if [ "$CREATE_DAEMON2" = "1" ]; then
        DAEMON2_PUBLIC="$(vm_ip slatefs-daemon2 public)"
        DAEMON2_PRIVATE="$(vm_ip slatefs-daemon2 private)"
    else
        DAEMON2_PUBLIC=""
        DAEMON2_PRIVATE=""
    fi

    write_rig_env

    log "waiting for SSH"
    wait_for_ssh "$CLIENT_PUBLIC"
    wait_for_ssh "$DAEMON1_PUBLIC"
    if [ "$CREATE_DAEMON2" = "1" ]; then
        wait_for_ssh "$DAEMON2_PUBLIC"
    fi

    log "rig env: $RIG_ENV"
}

build_linux_binaries() {
    require_tool docker
    mkdir -p "$LOCAL_OUTDIR/bin"
    log "building Linux release binaries in Docker ($DOCKER_IMAGE, $DOCKER_PLATFORM)"
    docker volume create slatefs-cargo-registry >/dev/null
    docker volume create slatefs-target-linux-amd64-bullseye >/dev/null
    docker run --rm \
        --platform "$DOCKER_PLATFORM" \
        -v "$PWD":/src:ro \
        -v slatefs-cargo-registry:/usr/local/cargo/registry \
        -v slatefs-target-linux-amd64-bullseye:/target \
        -v "$PWD/$LOCAL_OUTDIR/bin":/out \
        -e CARGO_TARGET_DIR=/target \
        -w /src \
        "$DOCKER_IMAGE" bash -ceu '
            cargo build --release -p slatefs-daemon -p slatefs-cli
            cp /target/release/slatefs /target/release/slatefsd /out/
        '
}

write_daemon_files() {
    mkdir -p "$LOCAL_OUTDIR/generated"
    cat > "$LOCAL_OUTDIR/generated/slatefs-azure.env" <<EOF
export AZURE_STORAGE_ACCOUNT_NAME=$(shell_quote "$STORAGE_ACCOUNT")
export AZURE_STORAGE_ACCESS_KEY=$(shell_quote "$STORAGE_ACCOUNT_KEY")
export AZURE_STORAGE_CONNECTION_STRING=$(shell_quote "$STORAGE_CONNECTION_STRING")
export AZURE_CONTAINER_NAME=$(shell_quote "$CONTAINER")
export OBJECT_STORE_URL=$(shell_quote "$OBJECT_STORE_URL")
EOF
    chmod 600 "$LOCAL_OUTDIR/generated/slatefs-azure.env"

    cat > "$LOCAL_OUTDIR/generated/slatefs.toml" <<EOF
[object_store]
url = "$OBJECT_STORE_URL"

[kms]
provider = "static"
key_hex = "0000000000000000000000000000000000000000000000000000000000000001"

[cache]
disk_path = "/mnt/slatefs-cache"
disk_bytes = 68719476736
disk_max_open_files = 256

[slatedb]
l0_sst_size_bytes = 16777216
max_unflushed_bytes = 268435456
l0_max_ssts = 64
l0_max_ssts_per_key = 16
l0_flush_parallelism = 2
compaction_max_sst_size_bytes = 67108864
compaction_max_concurrent = 2
compaction_max_fetch_tasks = 2

[metrics]
listen = "0.0.0.0:$METRICS_PORT"

[[exports]]
tenant = "$TENANT"
volume = "$VOLUME"
listen = "0.0.0.0:$NFS_PORT"
allowed_clients = ["10.42.0.0/16"]
squash = "none"
EOF
}

install_remote_deps() {
    local host="$1"
    log "installing dependencies on $host"
    ssh_cmd "$host" "sudo apt-get update -qq >/dev/null && sudo apt-get install -y -qq ca-certificates fio jq nfs-common >/dev/null && sudo mkdir -p /opt/slatefs /mnt/slatefs-cache /mnt/slatefs-bench/reports && sudo chown -R $ADMIN_USER:$ADMIN_USER /opt/slatefs /mnt/slatefs-cache /mnt/slatefs-bench"
}

copy_daemon_payload() {
    local host="$1"
    log "copying daemon payload to $host"
    scp_to "$LOCAL_OUTDIR/bin/slatefs" "$host" /opt/slatefs/slatefs
    scp_to "$LOCAL_OUTDIR/bin/slatefsd" "$host" /opt/slatefs/slatefsd
    scp_to "$LOCAL_OUTDIR/generated/slatefs.toml" "$host" /opt/slatefs/slatefs.toml
    scp_to "$LOCAL_OUTDIR/generated/slatefs-azure.env" "$host" /opt/slatefs/slatefs-azure.env
    ssh_cmd "$host" "chmod 700 /opt/slatefs/slatefs /opt/slatefs/slatefsd && chmod 600 /opt/slatefs/slatefs-azure.env"
}

setup_daemon1() {
    log "initializing tenant and volume on daemon1"
    ssh_cmd "$DAEMON1_PUBLIC" "set -euo pipefail; source /opt/slatefs/slatefs-azure.env; /opt/slatefs/slatefs -c /opt/slatefs/slatefs.toml tenant create '$TENANT'; /opt/slatefs/slatefs -c /opt/slatefs/slatefs.toml volume create '$TENANT' '$VOLUME'"
}

start_daemon1() {
    log "starting daemon1"
    ssh_cmd "$DAEMON1_PUBLIC" "set -euo pipefail; pkill -x slatefsd 2>/dev/null || true; source /opt/slatefs/slatefs-azure.env; nohup bash -lc 'ulimit -n 1024; source /opt/slatefs/slatefs-azure.env; RUST_LOG=info /opt/slatefs/slatefsd -c /opt/slatefs/slatefs.toml' >/opt/slatefs/slatefsd.log 2>&1 &"
    for _ in $(seq 1 75); do
        if ssh_cmd "$DAEMON1_PUBLIC" "timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/$NFS_PORT'" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    ssh_cmd "$DAEMON1_PUBLIC" "tail -120 /opt/slatefs/slatefsd.log" || true
    die "daemon1 NFS port did not open"
}

setup() {
    [ -n "$RIG_ENV" ] || die "set AZURE_PRODTEST_ENV for setup, or run all"
    source_rig_env "$RIG_ENV"
    build_linux_binaries
    write_daemon_files
    install_remote_deps "$CLIENT_PUBLIC"
    install_remote_deps "$DAEMON1_PUBLIC"
    if [ "$CREATE_DAEMON2" = "1" ]; then
        install_remote_deps "$DAEMON2_PUBLIC"
    fi
    copy_daemon_payload "$DAEMON1_PUBLIC"
    if [ "$CREATE_DAEMON2" = "1" ]; then
        copy_daemon_payload "$DAEMON2_PUBLIC"
    fi
    setup_daemon1
    start_daemon1
}

write_client_runner() {
    mkdir -p "$LOCAL_OUTDIR/generated"
    cat > "$LOCAL_OUTDIR/generated/client-fio-matrix.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

SERVER_IP="${SERVER_IP:?set SERVER_IP}"
SERVER_PORT="${SERVER_PORT:-12052}"
MNT="${MNT:-/mnt/slatefs-bench/mnt-primary}"
BENCH_DIR="$MNT/fio-matrix"
OUT="${OUT:-/mnt/slatefs-bench/reports/blob-cross-vm-fio-matrix-$(date -u +%Y%m%dT%H%M%SZ)}"
FIO_RUNTIME="${FIO_RUNTIME:-30}"
FIO_SIZE="${FIO_SIZE:-512m}"
FIO_JOBS="${FIO_JOBS:-4}"
FIO_BS_LIST="${FIO_BS_LIST:-4k 128k 1m}"
FIO_RW_LIST="${FIO_RW_LIST:-read write randread randwrite}"
FIO_PREFILL_BS="${FIO_PREFILL_BS:-4k}"
FIO_PREFILL_FSYNC="${FIO_PREFILL_FSYNC:-0}"
META_OPS="${META_OPS:-500}"
FIO_CMD_TIMEOUT="${FIO_CMD_TIMEOUT:-1800}"

mkdir -p "$OUT" "$MNT"
RESULTS="$OUT/results.tsv"
REPORT="$OUT/report.md"
LOG="$OUT/run.log"
: > "$RESULTS"
: > "$LOG"

cleanup() {
    sudo umount -f "$MNT" 2>/dev/null || true
}
trap cleanup EXIT

sudo umount -f "$MNT" 2>/dev/null || true
sudo mount -t nfs \
    -o "vers=3,tcp,nolock,soft,timeo=600,retrans=3,port=$SERVER_PORT,mountport=$SERVER_PORT" \
    "$SERVER_IP:/" "$MNT"
sudo mkdir -p "$BENCH_DIR"
sudo chown "$(id -u):$(id -g)" "$BENCH_DIR"

run_fio_json() {
    local json="$1"
    shift
    timeout "$FIO_CMD_TIMEOUT" /usr/bin/fio "$@" --output-format=json --output="$json" >>"$LOG" 2>&1
}

extract_row() {
    local rw="$1"
    local bs="$2"
    local json="$3"
    local dir op iops bw mean p99
    case "$rw" in
        read|randread) dir=read ;;
        write|randwrite) dir=write ;;
        *) echo "unknown fio rw mode: $rw" >&2; exit 1 ;;
    esac
    op=".jobs[0].$dir"
    iops=$(jq -r "$op.iops" "$json")
    bw=$(jq -r "($op.bw_bytes / 1048576)" "$json")
    mean=$(jq -r "($op.clat_ns.mean / 1000000)" "$json")
    p99=$(jq -r "$op.clat_ns.percentile[\"99.000000\"] / 1000000" "$json")
    printf "%s\t%s\t%.0f\t%.1f\t%.3f\t%.3f\n" "$rw" "$bs" "$iops" "$bw" "$mean" "$p99" >> "$RESULTS"
}

needs_read_source() {
    [[ " $FIO_RW_LIST " == *" read "* || " $FIO_RW_LIST " == *" randread "* ]]
}

for bs in $FIO_BS_LIST; do
    readfile="$BENCH_DIR/read-source-$bs.dat"
    if needs_read_source; then
        echo "== prefill read source bs=$bs" | tee -a "$LOG"
        timeout "$FIO_CMD_TIMEOUT" /usr/bin/fio \
            --name="prefill-$bs" \
            --directory="$BENCH_DIR" \
            --filename="$(basename "$readfile")" \
            --rw=write \
            --bs="$FIO_PREFILL_BS" \
            --size="$FIO_SIZE" \
            --ioengine=sync \
            --numjobs="$FIO_JOBS" \
            --group_reporting=1 \
            --fallocate=none \
            --end_fsync="$FIO_PREFILL_FSYNC" \
            --output=/dev/null >>"$LOG" 2>&1
    fi
    for rw in $FIO_RW_LIST; do
        file="$BENCH_DIR/${rw}-${bs}.dat"
        [[ "$rw" == read || "$rw" == randread ]] && file="$readfile"
        json="$OUT/${rw}-${bs}.json"
        echo "== fio rw=$rw bs=$bs" | tee -a "$LOG"
        run_fio_json "$json" \
            --name="$rw-$bs" \
            --directory="$BENCH_DIR" \
            --filename="$(basename "$file")" \
            --rw="$rw" \
            --bs="$bs" \
            --size="$FIO_SIZE" \
            --runtime="$FIO_RUNTIME" \
            --time_based=1 \
            --ioengine=sync \
            --numjobs="$FIO_JOBS" \
            --group_reporting=1 \
            --fallocate=none \
            --end_fsync=1
        extract_row "$rw" "$bs" "$json"
    done
done

meta_dir="$BENCH_DIR/meta"
mkdir -p "$meta_dir"
start_ns=$(date +%s%N)
for i in $(seq 1 "$META_OPS"); do
    f="$meta_dir/file-$i"
    printf "%s\n" "$i" > "$f"
    stat "$f" >/dev/null
    rm "$f"
done
end_ns=$(date +%s%N)
elapsed=$(awk -v s="$start_ns" -v e="$end_ns" 'BEGIN { printf "%.3f", (e-s)/1000000000 }')
ops=$(awk -v n="$META_OPS" -v e="$elapsed" 'BEGIN { printf "%.1f", (n*3)/e }')

{
    echo "# SlateFS Azure Blob cross-VM fio Report"
    echo
    echo "- server: $SERVER_IP:$SERVER_PORT"
    echo "- runtime: ${FIO_RUNTIME}s"
    echo "- size per job: $FIO_SIZE"
    echo "- jobs: $FIO_JOBS"
    echo "- read-source prefill block size: $FIO_PREFILL_BS"
    echo "- read-source prefill end_fsync: $FIO_PREFILL_FSYNC"
    echo "- mount: kernel NFSv3, soft,timeo=600,retrans=3"
    echo
    echo "| workload | block | IOPS | MiB/s | mean ms | p99 ms |"
    echo "|---|---:|---:|---:|---:|---:|"
    awk -F "\t" '{ printf "| %s | %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5, $6 }' "$RESULTS"
    echo
    echo "## Metadata Smoke"
    echo
    echo "- create/stat/unlink ops: $((META_OPS * 3))"
    echo "- elapsed seconds: $elapsed"
    echo "- metadata ops/s: $ops"
} | tee "$REPORT"

echo "$OUT" > "$OUT/remote-out.txt"
echo "$OUT"
EOF
    chmod +x "$LOCAL_OUTDIR/generated/client-fio-matrix.sh"
}

write_observability_files() {
    mkdir -p \
        "$LOCAL_OUTDIR/observability/prometheus" \
        "$LOCAL_OUTDIR/observability/grafana/provisioning/datasources" \
        "$LOCAL_OUTDIR/observability/grafana/provisioning/dashboards" \
        "$LOCAL_OUTDIR/observability/grafana/dashboards"

    local prom_name="slatefs-prometheus-$RUN_ID"
    cat > "$LOCAL_OUTDIR/observability/prometheus/prometheus.yml" <<EOF
global:
  scrape_interval: 5s
  evaluation_interval: 5s
scrape_configs:
  - job_name: slatefs-azure-daemon1
    static_configs:
      - targets: ['host.docker.internal:$LOCAL_METRICS_PORT']
        labels:
          instance: daemon1
          rig: azure-prodtest
          run_id: "$RUN_ID"
EOF

    cat > "$LOCAL_OUTDIR/observability/grafana/provisioning/datasources/prometheus.yml" <<EOF
apiVersion: 1
datasources:
  - name: Prometheus
    uid: prometheus
    type: prometheus
    access: proxy
    url: http://$prom_name:9090
    isDefault: true
    editable: true
EOF

    cat > "$LOCAL_OUTDIR/observability/grafana/provisioning/dashboards/slatefs.yml" <<EOF
apiVersion: 1
providers:
  - name: SlateFS
    orgId: 1
    folder: SlateFS
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
EOF

    cp monitoring/slatefs-grafana-dashboard.json \
        "$LOCAL_OUTDIR/observability/grafana/dashboards/slatefs-grafana-dashboard.json"
}

start_ssh_tunnel() {
    log "opening metrics SSH tunnel localhost:$LOCAL_METRICS_PORT -> daemon1:$METRICS_PORT"
    set_ssh_args
    ssh "${SSH_ARGS[@]}" \
        -N \
        -L "$LOCAL_METRICS_PORT:127.0.0.1:$METRICS_PORT" \
        "$ADMIN_USER@$DAEMON1_PUBLIC" &
    SSH_TUNNEL_PID=$!
    sleep 2
}

start_observability() {
    [ "$OBSERVABILITY" = "1" ] || return 0
    require_tool docker
    write_observability_files
    start_ssh_tunnel

    local net="slatefs-prodtest-$RUN_ID"
    local prom_name="slatefs-prometheus-$RUN_ID"
    local grafana_name="slatefs-grafana-$RUN_ID"

    docker network create "$net" >/dev/null 2>&1 || true
    docker rm -f "$prom_name" "$grafana_name" >/dev/null 2>&1 || true

    log "starting Prometheus on localhost:$PROMETHEUS_PORT"
    docker run -d \
        --name "$prom_name" \
        --network "$net" \
        --add-host host.docker.internal:host-gateway \
        -p "$PROMETHEUS_PORT:9090" \
        -v "$PWD/$LOCAL_OUTDIR/observability/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
        prom/prometheus:v2.53.0 >/dev/null

    log "starting Grafana on localhost:$GRAFANA_PORT"
    docker run -d \
        --name "$grafana_name" \
        --network "$net" \
        -p "$GRAFANA_PORT:3000" \
        -e GF_SECURITY_ADMIN_USER=admin \
        -e GF_SECURITY_ADMIN_PASSWORD="$GRAFANA_PASSWORD" \
        -v "$PWD/$LOCAL_OUTDIR/observability/grafana/provisioning:/etc/grafana/provisioning:ro" \
        -v "$PWD/$LOCAL_OUTDIR/observability/grafana/dashboards:/var/lib/grafana/dashboards:ro" \
        grafana/grafana:11.0.0 >/dev/null

    cat > "$LOCAL_OUTDIR/observability/urls.txt" <<EOF
Grafana: http://localhost:$GRAFANA_PORT/d/slatefs-daemon/slatefs-daemon?orgId=1&refresh=5s
Prometheus: http://localhost:$PROMETHEUS_PORT
EOF
    log "Grafana URL: http://localhost:$GRAFANA_PORT/d/slatefs-daemon/slatefs-daemon?orgId=1&refresh=5s"
}

run_fio() {
    [ -n "$RIG_ENV" ] || die "set AZURE_PRODTEST_ENV for run-fio, or run all"
    source_rig_env "$RIG_ENV"
    write_client_runner
    start_observability

    local remote_runner="/mnt/slatefs-bench/client-fio-matrix.sh"
    local remote_out="/mnt/slatefs-bench/reports/$RUN_ID/fio-matrix"
    scp_to "$LOCAL_OUTDIR/generated/client-fio-matrix.sh" "$CLIENT_PUBLIC" "$remote_runner"
    ssh_cmd "$CLIENT_PUBLIC" "chmod +x '$remote_runner'"

    log "running fio matrix from client VM"
    ssh_cmd "$CLIENT_PUBLIC" \
        "SERVER_IP='$DAEMON1_PRIVATE' SERVER_PORT='$NFS_PORT' OUT='$remote_out' FIO_RUNTIME='$FIO_RUNTIME' FIO_SIZE='$FIO_SIZE' FIO_JOBS='$FIO_JOBS' FIO_BS_LIST='$FIO_BS_LIST' FIO_RW_LIST='$FIO_RW_LIST' FIO_PREFILL_BS='$FIO_PREFILL_BS' FIO_PREFILL_FSYNC='$FIO_PREFILL_FSYNC' META_OPS='$META_OPS' '$remote_runner'" \
        | tee "$LOCAL_OUTDIR/artifacts/client-fio-run.log"

    collect_artifacts
}

collect_artifacts() {
    [ -n "$RIG_ENV" ] || die "set AZURE_PRODTEST_ENV for collect, or run all"
    source_rig_env "$RIG_ENV"
    mkdir -p "$LOCAL_OUTDIR/artifacts"

    log "collecting client fio artifacts"
    scp_from "$CLIENT_PUBLIC" "/mnt/slatefs-bench/reports/$RUN_ID/fio-matrix" "$LOCAL_OUTDIR/artifacts/" || true

    log "collecting daemon logs"
    scp_from "$DAEMON1_PUBLIC" /opt/slatefs/slatefsd.log "$LOCAL_OUTDIR/artifacts/daemon1.log" || true
    if [ "$CREATE_DAEMON2" = "1" ]; then
        scp_from "$DAEMON2_PUBLIC" /opt/slatefs/slatefsd.log "$LOCAL_OUTDIR/artifacts/daemon2.log" || true
    fi

    az vm list -g "$RESOURCE_GROUP" -d -o table | tee "$LOCAL_OUTDIR/artifacts/vm-state.txt" >/dev/null
}

deallocate_vms() {
    [ -n "${RESOURCE_GROUP:-}" ] || return 0
    log "deallocating VMs in $RESOURCE_GROUP"
    local ids
    ids="$(az vm list -g "$RESOURCE_GROUP" --query '[].id' -o tsv 2>/dev/null || true)"
    [ -n "$ids" ] || return 0
    # shellcheck disable=SC2086
    az vm deallocate --ids $ids -o none
    if [ -n "${LOCAL_OUTDIR:-}" ]; then
        mkdir -p "$LOCAL_OUTDIR/artifacts"
        az vm list -g "$RESOURCE_GROUP" -d -o table \
            > "$LOCAL_OUTDIR/artifacts/vm-state-after-deallocate.txt" 2>/dev/null || true
    fi
}

delete_resource_group() {
    [ -n "${RESOURCE_GROUP:-}" ] || return 0
    log "deleting resource group $RESOURCE_GROUP"
    az group delete --name "$RESOURCE_GROUP" --yes --no-wait
}

case "$ACTION" in
    help|-h|--help)
        usage
        ;;
    provision)
        provision
        ;;
    setup)
        setup
        ;;
    run-fio)
        DEALLOCATE_ON_EXIT=1
        run_fio
        ;;
    observability)
        [ -n "$RIG_ENV" ] || die "set AZURE_PRODTEST_ENV for observability"
        source_rig_env "$RIG_ENV"
        start_observability
        ;;
    collect)
        collect_artifacts
        ;;
    deallocate)
        ensure_azure
        [ -n "$RIG_ENV" ] || die "set AZURE_PRODTEST_ENV for deallocate"
        source_rig_env "$RIG_ENV"
        deallocate_vms
        ;;
    delete-rg)
        ensure_azure
        [ -n "$RIG_ENV" ] || die "set AZURE_PRODTEST_ENV for delete-rg"
        source_rig_env "$RIG_ENV"
        delete_resource_group
        ;;
    all)
        ensure_azure
        DEALLOCATE_ON_EXIT=1
        provision
        setup
        run_fio
        ;;
    *)
        usage
        die "unknown action: $ACTION"
        ;;
esac
