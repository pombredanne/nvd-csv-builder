#!/bin/sh

download(){
	year=$(date | cut -d ' ' -f6)
	curl -O "https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-[2002-$year].xml.gz"
	gunzip nvdcve-*
}

createcsv(){
	ls *.xml | cut -d '-' -f3 | cut -d '.' -f1 | xargs -L1 python parse.py
}

compile(){
	cat 2002.csv > all.csv
	sed '1d' 2003.csv >> all.csv
	sed '1d' 2004.csv >> all.csv
	sed '1d' 2005.csv >> all.csv
	sed '1d' 2006.csv >> all.csv
	sed '1d' 2007.csv >> all.csv
	sed '1d' 2008.csv >> all.csv
	sed '1d' 2009.csv >> all.csv
	sed '1d' 201*.csv >> all.csv
}

main(){
	download
	createcsv
	compile
}

main
