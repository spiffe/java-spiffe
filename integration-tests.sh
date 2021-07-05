#!/usr/bin/env bash

# Start a SPIRE Server and Agent and run the integration tests
# Only works on Linux.

set -euf -o pipefail

# Some cleanup: kill spire processes that could have remained from previous run
killall -9 spire-agent || true
killall -9 spire-server || true
rm -rf spire-0.12.3

# Install and run a SPIRE server
curl -s -N -L https://github.com/spiffe/spire/releases/download/v0.12.3/spire-0.12.3-linux-x86_64-glibc.tar.gz | tar xz
pushd spire-0.12.3
bin/spire-server run -config conf/server/server.conf &
sleep 5

# Run the SPIRE agent with the join token
bin/spire-server token generate -spiffeID spiffe://example.org/myagent > token
cut -d ' ' -f 2 token > token_stripped
bin/spire-agent run -config conf/agent/agent.conf -joinToken "$(< token_stripped)" &
sleep 5

# Register the workload through UID with the SPIFFE ID "spiffe://example.org/myservice"
bin/spire-server entry create -parentID spiffe://example.org/myagent -spiffeID spiffe://example.org/myservice -selector unix:uid:$(id -u)
sleep 5
popd

export SPIFFE_ENDPOINT_SOCKET="unix:/tmp/agent.sock"

# Run only the integration tests
./gradlew integrationTest

# Cleanup
killall -9 spire-agent || true
killall -9 spire-server || true
rm -rf spire-0.12.3