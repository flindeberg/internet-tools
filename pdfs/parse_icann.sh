#!/bin/bash

echo "Make sure you have python and scrapy installed...."
echo "And verapdf if you want to verify them as well"

mkdir -p pdfs

echo "Starting spider, will take a couple of hours"

scrapy runspider -L WARNING scrape_icann_pdfs.py

files=$(ll pdfs/ | wcl -l)

echo "Found ${files} pdfs!"

echo "Verifying PDFs for PDF/A compliance... (will take a while)"

verapdf --format text pdfs/*.pdf | grep "PASS"

echo "DONE"