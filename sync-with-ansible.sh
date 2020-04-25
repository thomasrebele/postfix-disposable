#!/bin/bash

sovereign_dir="$1"

if [ "$sovereign_dir" == "" ]; then
	echo "usage: <sovereign-dir>"
	exit 1
fi

for i in $(find -type f ! -path './.git/*' ! -path './__pycache__/*'); do
	case "$i" in
		./sync-with*|./README.md|./.gitignore|./example_disposable_config.py|./disposable_config.py)
			echo "ignore $i"
			continue;
			;;
		./postfix_pgsql-disposable-alias-maps.cf.j2)
			dst="roles/mailserver/templates/etc_postfix_pgsql-disposable-alias-maps.cf.j2"
			;;
		./postfix_disposable.py)
			dst="roles/mailserver/files/etc_postfix_postfix_disposable.py"
			;;
		*)
			echo "warning: unknown $i"
			break;
	esac

	#if cmp --silent "$i" "$sovereign_dir/$dst"; then
	#	echo "no changes for $i"
	#else
		meld "$i" "$sovereign_dir/$dst"
	#fi

done
