#!/bin/bash

echo What IP Address can I recon for you today?

read ipadd

nmap -O $ipadd

