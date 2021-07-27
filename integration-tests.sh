#!/usr/bin/env bash

# Start a SPIRE Server and Agent and run the integration tests
# Only works on Linux.

set -euf -o pipefail

spire_folder="spire-858d04b"

function cleanup() {
  killall -9 spire-agent || true
  killall -9 spire-server || true
  rm -f /tmp/spire-server/private/api.sock
  rm -f /tmp/spire-agent/public/api.sock
  rm -rf ${spire_folder}
}

# Some cleanup: kill spire processes that could have remained from previous run
cleanup

# Install and run a SPIRE server
curl -s -N -L https://github.com/spiffe/spire/releases/download/v1.0.0/spire-1.0.0-linux-x86_64-glibc.tar.gz | tar xz
pushd "${spire_folder}"
bin/spire-server run -config conf/server/server.conf &
sleep 10

# Run the SPIRE agent with the join token
bin/spire-server token generate -spiffeID spiffe://example.org/myagent > token
cut -d ' ' -f 2 token > token_stripped
bin/spire-agent run -config conf/agent/agent.conf -joinToken "$(< token_stripped)" &
sleep 10

# Register the workload through UID with the SPIFFE ID "spiffe://example.org/myservice"
bin/spire-server entry create -parentID spiffe://example.org/myagent -spiffeID spiffe://example.org/myservice -selector unix:uid:$(id -u)
sleep 10
popd

export SPIFFE_ENDPOINT_SOCKET="unix:/tmp/spire-agent/public/api.sock"

# Run only the integration tests
./gradlew integrationTest

cleanup
