#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
version=$(node -p "require('./ai-studio-extension/package.json').webcodexRelease.agent")
mkdir -p bin/aix
go build -trimpath -tags aistudio -ldflags "-X webcodex/internal/buildinfo.Version=$version" -o bin/aix/webcodex-agent ./cmd/agent
printf 'Built local AI Studio agent in bin/aix/webcodex-agent\n'
