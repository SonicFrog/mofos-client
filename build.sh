#!/bin/sh

readonly CONFIG_DIR=./config

[[ -d .tup ]] || tup init

for i in $@; do
	case "$i" in
		test)
			tup variant $CONFIG_DIR/test.config
			tup build-test
			;;

		release)
			tup variant $CONFIG_DIR/release.config
			tup build-release
			;;

		clean)
			rm -rf build-*
			;;

		*)
			printf "Invalid argument $i\n"
			exit 1
			;;
	esac
done
