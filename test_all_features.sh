#!/usr/bin/env sh

cargo hack test \
	--feature-powerset \
	--include-features smol-runtime,fetch-sync,fetch-smol,tls-dynamic,rustls,embedded-tls \
	--mutually-exclusive-features fetch-sync,fetch-smol \
	--exclude-features default \
	--exclude-all-features \
	--keep-going
