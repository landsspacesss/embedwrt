set(srcs "my_wifi_router.c" "doh_relay.c" "led_off.c" "led_strip_encoder.c"
         "clients.c" "ap_dhcp.c" "static_leases.c" "portmap.c"
         "dns_rules.c" "dot_client.c" "ap_acl.c" "web_auth.c" "devices.c"
         "fw_update.c")

# The vendored DHCP server and IDF's own define the same dhcps_* symbols, so
# exactly one may be compiled. CONFIG_USE_OWN_DHCPS pairs with CONFIG_LWIP_DHCPS=n.
if(CONFIG_USE_OWN_DHCPS)
    list(APPEND srcs "dhcps/vendored_dhcps.c")
endif()

idf_component_register(SRCS ${srcs}
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES esp_wifi nvs_flash esp_event esp_netif esp_timer
                                  esp_http_client esp_http_server esp-tls mbedtls lwip
                                  esp_driver_rmt espressif__mdns app_update
                    EMBED_TXTFILES "certs/gsr5.pem")

# The build channel, from the top-level CMakeLists.txt (and, in CI, from
# $GITHUB_REPOSITORY). These have to be attached to this component explicitly:
# add_compile_definitions() at the top level does not reach an ESP-IDF
# component, and that failure is silent - the macros stay undefined, the release
# build behaves like a development one, and nothing says so.
#
# fw_update.c uses them to decide whether updates exist at all, and where from.
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    FW_RELEASE_BUILD=$<BOOL:${EMBEDWRT_RELEASE}>
    FW_DEFAULT_REPO="${EMBEDWRT_REPO}")
