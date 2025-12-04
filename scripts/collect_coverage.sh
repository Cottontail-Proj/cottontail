#!/bin/bash

source_path=$1
gcovr -r $source_path  -s | tail -3 | head -3 > all_coverage.txt
tr '\n' ' ' < all_coverage.txt | sed 's/ $/\n/' > temp.txt
#cat temp.txt >> all_records.txt

while IFS= read -r line; do
  # Append the current time to each line
  echo "$line $(date)" >> all_records.txt
done < temp.txt