#!/bin/bash

if [ "$#" -ne 1 ]; then
  echo -e "\e[1;37mUsage: $0 <domain>"
  exit 1
fi

domain="$1"

# ------------------Get domains via assetfinder
mapfile -t assetfinder_domains < <(assetfinder -subs-only "$domain")
echo -e "\x1b[1;38;5;12m\n[INFO] assetfinder finished\e[1;37m"
# ------------------Get domains via assetfinder

# ------------------Get domains via crt.sh
mapfile -t crtsh_domains < <(curl -s "https://crt.sh/?q=$domain&output=json" \
  | jq \
  | grep -E 'common_name|name_value' \
  | sort -u \
  | awk -F ': "' '{print $2}' \
  | sed 's/",//g' \
  | awk '{gsub(/\\n/, "\n"); print}' \
  | sort -u
)
echo -e "\x1b[1;38;5;12m[INFO] crt.sh finished\e[1;37m"
# ------------------Get domains via crt.sh

combined_domains=($(printf "%s\n" "${crtsh_domains[@]}" "${assetfinder_domains[@]}" | sort -u))

# ------------------Check with nslookup + httprobe
echo -e "\n\e[1;37m[nslookup & httprobe results]\n"

for d in "${combined_domains[@]}"; do
  result=$(nslookup "$d" 2>/dev/null)

  if echo "$result" | grep -q -E "Can't find|can't find|communications error to"; then
    echo -e "\e[1;31m[-] $d"
    continue
  fi

  ip=$(echo "$result" | grep "Address:" | sed -n '2p' | awk '{print $2}')

  PROBE_RESULT=$(echo "$d" | httprobe)
  HTTP_COUNT=$(echo "$PROBE_RESULT" | grep -c "^http://")
  HTTPS_COUNT=$(echo "$PROBE_RESULT" | grep -c "^https://")

  if [ "$HTTP_COUNT" -gt 0 ] && [ "$HTTPS_COUNT" -gt 0 ]; then

    protocols="\e[1;34m[http] [https]\e[0m"
  elif [ "$HTTP_COUNT" -gt 0 ]; then

    protocols="\e[1;33m[http]\e[0m"
  elif [ "$HTTPS_COUNT" -gt 0 ]; then

    protocols="\e[1;36m[https]\e[0m"
  else
    protocols=""
  fi

  if [ -n "$ip" ]; then
    echo -e "\e[1;32m[+] $d $protocols \e[1;32m($ip)\e[0m"
  else
    echo -e "\e[1;32m[+] $d $protocols"
  fi
done
# ------------------Check with nslookup + httprobe
