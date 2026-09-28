# EmbedWRT: ESP32-S3 WiFi repeater (NAT) with a DNS-over-HTTPS/DoT relay
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# ---------------------------------------------------------------------------
# Build channel, decided before project() because it affects PROJECT_VER.
#
# A *release* build can update itself from a release feed. A *development*
# build cannot, at all: the update machinery is not compiled in, and the panel
# says so instead of offering controls that do nothing.
#
# Deciding this at build time is what makes a runtime guard unnecessary. The
# alternative - one binary that works out at run time whether its feed can be
# trusted - needs heuristics about where the build came from and whether the
# tree was clean, and gets them wrong silently. Here the answer is a property
# of how the artifact was produced, and it is known exactly.
#
# Local builds are development builds, so a plain `idf.py build` can never
# produce something that quietly replaces itself with upstream's firmware. CI
# passes ON, which also makes a release build a deliberate act.
#
#     idf.py build                            # development
#     idf.py -DEMBEDWRT_RELEASE=ON build      # release
# ---------------------------------------------------------------------------
set(EMBEDWRT_RELEASE "OFF" CACHE BOOL "Build a release: automatic updates enabled")

# Which repository this build updates from. CI passes $GITHUB_REPOSITORY, so a
# fork's release build points at the fork rather than at upstream: the default
# is correct by construction for whoever built it, which is the other half of
# why no runtime check is needed.
set(EMBEDWRT_REPO "landsspacesss/embedwrt" CACHE STRING
    "owner/repo this build updates from")

# Bump this when you want to tell two builds apart in the panel. The app
# descriptor also carries the compile date and time, so builds are already
# distinguishable; this is the human-readable label the panel shows.
set(PROJECT_VER "1.5.0")

# A development build says so in its version, for two reasons.
#
# It is honest in the panel: "1.5.0-dev" is not a release and does not pretend
# to be. And it closes a real footgun - make_release.py refuses to publish when
# the image's embedded version disagrees with PROJECT_VER, so a local build
# cannot be published as a release by accident. Without the suffix that check
# would pass and the release would ship with updates disabled, which nobody
# would notice until a device refused to update itself.
if(NOT EMBEDWRT_RELEASE)
    set(PROJECT_VER "${PROJECT_VER}-dev")
endif()

project(embedwrt)
