# EmbedWRT: ESP32-S3 WiFi repeater (NAT) with a DNS-over-HTTPS/DoT relay
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Bump this when you want to tell two builds apart in the panel. The app
# descriptor also carries the compile date and time, so builds are already
# distinguishable; this is the human-readable label the panel shows.
set(PROJECT_VER "1.4.2")

# Build provenance - which repository this firmware came from, and whether the
# tree had local changes - is generated as a header by a build step in
# main/CMakeLists.txt, not here. Two reasons it is not done at configure time:
# add_compile_definitions() at this level does not reach ESP-IDF components
# (and fails silently, leaving the guard permanently disarmed), and the dirty
# flag changes when a source file is edited, which does not make CMake
# re-configure. See tools/gen_build_info.cmake.

project(embedwrt)
