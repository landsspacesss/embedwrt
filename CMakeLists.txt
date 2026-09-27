# EmbedWRT: ESP32-S3 WiFi repeater (NAT) with a DNS-over-HTTPS/DoT relay
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Bump this when you want to tell two builds apart in the panel. The app
# descriptor also carries the compile date and time, so builds are already
# distinguishable; this is the human-readable label the panel shows.
set(PROJECT_VER "1.3.1")

# ---------------------------------------------------------------------------
# Build provenance, baked in as compile definitions.
#
# Two things are recorded: which repository this firmware was built from, and
# whether the working tree had uncommitted changes. fw_update.c uses them to
# refuse to replace a build that did not come from the feed it is pointed at.
#
# Without this, anyone who forks or edits the source and flashes it would have
# their work silently overwritten by the release the default feed happens to
# serve - which is upstream, not them. The repository identity catches a fork
# (its origin differs) and the dirty flag catches local edits.
#
# Absent git, or a source tarball with no repository, leaves both empty and the
# build is treated as unattributed: it will not accept an automatic update.
# ---------------------------------------------------------------------------
execute_process(
    COMMAND git config --get remote.origin.url
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    OUTPUT_VARIABLE EMBEDWRT_ORIGIN
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET)

execute_process(
    COMMAND git status --porcelain
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    OUTPUT_VARIABLE EMBEDWRT_STATUS
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET)

if(EMBEDWRT_STATUS)
    set(EMBEDWRT_DIRTY 1)
else()
    set(EMBEDWRT_DIRTY 0)
endif()

# Strip anything that would break a C string literal. A URL should not contain
# these, but a build should not fail on a strange remote either.
string(REGEX REPLACE "[^A-Za-z0-9:/._@-]" "" EMBEDWRT_ORIGIN_SAFE "${EMBEDWRT_ORIGIN}")

message(STATUS "EmbedWRT build provenance: origin='${EMBEDWRT_ORIGIN_SAFE}' dirty=${EMBEDWRT_DIRTY}")

# Hand the values to main/CMakeLists.txt through the cache. Setting them here as
# plain variables would not be visible there, and add_compile_definitions() at
# this level does NOT reach ESP-IDF components - the definitions silently do not
# apply, which is worse than an error because the feature looks present and
# simply never triggers.
set(EMBEDWRT_ORIGIN "${EMBEDWRT_ORIGIN_SAFE}" CACHE INTERNAL "git origin of this build")
set(EMBEDWRT_DIRTY "${EMBEDWRT_DIRTY}" CACHE INTERNAL "1 when the source tree had local changes")

project(embedwrt)
