# EmbedWRT: ESP32-S3 WiFi repeater (NAT) with a DNS-over-HTTPS/DoT relay
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Bump this when you want to tell two builds apart in the panel. The app
# descriptor also carries the compile date and time, so builds are already
# distinguishable; this is the human-readable label the panel shows.
set(PROJECT_VER "1.2.1")

project(embedwrt)
