#!/usr/bin/env sh

cargo hack test \
	--feature-powerset \
	--include-features ping,smol-runtime,fetch-sync,fetch-smol,hash,tls-dynamic,rustls,embedded-tls \
	--mutually-exclusive-features fetch-sync,fetch-smol \
	--exclude-features default \
	--exclude-all-features \
	--keep-going
