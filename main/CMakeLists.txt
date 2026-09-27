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

# Build provenance, computed by the top-level CMakeLists.txt. It has to be
# attached to this component explicitly: add_compile_definitions() at the top
# level does not reach ESP-IDF components, and the failure is silent - the
# macros stay undefined, the guard never fires, and the feature looks present.
#
# fw_update.c uses these to refuse a feed that is not this build's own repository.
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    FW_BUILD_REPO="${EMBEDWRT_ORIGIN}"
    FW_BUILD_DIRTY=${EMBEDWRT_DIRTY})
