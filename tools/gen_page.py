#!/usr/bin/env python3
"""Generate the html_page C literal for main/my_wifi_router.c.

Written this way because the page is ~27 KB of HTML/JS embedded as a C string:
hand-escaping it is error-prone, whereas here the document is written naturally
and the quoting is mechanical. Emits one C string literal per line.
"""
import re
import sys

HTML = r"""<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>EmbedWRT</title>
<link rel='icon' href='data:,'>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,'Noto Sans SC','Microsoft YaHei',sans-serif;background:#f4f6f9;display:flex;justify-content:center;align-items:flex-start;min-height:100vh;color:#1e293b;padding:16px 0}
.card{background:#fff;border-radius:12px;box-shadow:0 10px 25px rgba(0,0,0,0.05);width:100%;max-width:420px;overflow:hidden}
.header{background:linear-gradient(135deg,#1e293b,#334155);padding:20px 24px;text-align:center;color:#fff;position:relative}
.header-icon svg{width:32px;height:32px;fill:#60a5fa}
.header h1{font-size:18px;font-weight:700;color:#f1f5f9;letter-spacing:0.5px}
.header .subtitle{font-size:11px;color:#94a3b8;margin-top:4px}
#lang-btn{position:absolute;top:12px;right:12px;background:rgba(255,255,255,.12);color:#e2e8f0;border:1px solid rgba(255,255,255,.25);border-radius:6px;padding:4px 9px;font-size:11px;font-weight:600;cursor:pointer}
#lang-btn:hover{background:rgba(255,255,255,.22)}
#auth-btn{position:absolute;top:12px;left:12px;background:rgba(255,255,255,.12);color:#e2e8f0;border:1px solid rgba(255,255,255,.25);border-radius:6px;padding:4px 9px;font-size:11px;font-weight:600;cursor:pointer}
#auth-btn:hover{background:rgba(255,255,255,.22)}
#modal{display:none;position:fixed;inset:0;background:rgba(15,23,42,.55);align-items:center;justify-content:center;padding:20px;z-index:50}
#modal .box{background:#fff;border-radius:12px;padding:20px;width:100%;max-width:330px}
#modal h3{font-size:15px;margin-bottom:14px;color:#0f172a}
#modal .err{color:#b91c1c;font-size:12px;min-height:16px;margin-top:8px}
#guest-view{display:none;padding:22px}
.tabs{display:flex;border-bottom:1px solid #e2e8f0}
.tab{flex:1;text-align:center;padding:14px 6px;font-size:13px;font-weight:600;color:#64748b;background:#f8fafc;border:none;cursor:pointer}
.tab.active{color:#3b82f6;background:#fff;border-bottom:2px solid #3b82f6}
.tab-content{display:none;padding:20px}
.tab-content.active{display:block}
.header-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
h1{font-size:19px;color:#0f172a}
h2{font-size:14px;color:#334155;margin:22px 0 8px;padding-top:16px;border-top:1px solid #e2e8f0}
h2:first-of-type{margin-top:8px;padding-top:0;border-top:none}
.refresh-btn{background:#e2e8f0;color:#475569;border:none;padding:7px 11px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer}
.refresh-btn:hover{background:#cbd5e1}
#status-msg{text-align:center;font-size:13px;margin-bottom:8px;font-weight:500;padding:8px;border-radius:6px;background:#f8fafc}
.hint{font-size:11px;color:#94a3b8;margin-bottom:10px;line-height:1.5}
.network-list{border:1px solid #e2e8f0;border-radius:8px;margin-bottom:14px;max-height:200px;overflow-y:auto;background:#fafafa}
.network-item{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-bottom:1px solid #e2e8f0;cursor:pointer}
.network-item:last-child{border-bottom:none}
.network-item:hover{background:#f1f5f9}
.net-info{display:flex;align-items:center;gap:8px;font-size:14px;color:#334155}
.icon{width:16px;height:16px}
.icon.secure{fill:#94a3b8}
.form-group{margin-bottom:12px}
label{display:block;font-size:12px;color:#475569;margin-bottom:5px;font-weight:500}
input,select{width:100%;padding:9px 11px;border:1px solid #cbd5e1;border-radius:6px;font-size:14px;outline:none;background:#fff}
input:focus,select:focus{border-color:#3b82f6}
.btn{width:100%;background:#3b82f6;color:white;border:none;padding:11px;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;margin-top:4px}
.btn:hover{background:#2563eb}
.btn.danger{background:#ef4444}
.btn.danger:hover{background:#dc2626}
.btn.small{padding:8px;font-size:12px}
.loading{text-align:center;padding:18px;font-size:13px;color:#64748b}
.info-box{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:11px;margin-bottom:12px;font-size:12px;color:#166534;line-height:1.5}
.info-box.warn{background:#fef2f2;border-color:#fecaca;color:#991b1b}
.row{display:flex;gap:8px}
.row>*{flex:1}
.footer{margin-top:22px;padding-top:14px;border-top:1px solid #e2e8f0;text-align:center;font-size:11px;color:#94a3b8;line-height:1.6}
.footer a{color:#64748b;text-decoration:none}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
.testout{font-size:11px;line-height:1.7;font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
</style></head><body>
<div class='card'>
  <div class='header'>
    <button id='lang-btn' onclick='toggleLang()'>中文</button>
    <button id='auth-btn' onclick='authButton()'>Log in</button>
    <div class='header-icon'><svg viewBox='0 0 24 24'><path d='M1 9l2 2c4.97-4.97 13.03-4.97 18 0l2-2C16.93 2.93 7.08 2.93 1 9zm8 8l3 3 3-3c-1.65-1.66-4.34-1.66-6 0zm-4-4l2 2c2.76-2.76 7.24-2.76 10 0l2-2C15.14 9.14 8.87 9.14 5 13z'/></svg></div>
    <h1 data-i18n='title'>EmbedWRT</h1>
    <div class='subtitle' data-i18n='subtitle'>WiFi NAT router &middot; DoH / DoT</div>
  </div>
  <div id='guest-view'>
    <div class='hint' id='guest-body' style='margin:0 0 14px' data-i18n='guest_body'></div>
    <div id='guest-ident' class='hint'></div>
    <div id='guest-devices'></div>
    <button class='btn' style='margin-top:14px' onclick='showLogin()' data-i18n='login_btn'>Log in</button>
  </div>
  <div id='admin-view'>
  <div class='tabs'>
    <button class='tab active' onclick='switchTab("wifi",event)' data-i18n='tab_wifi'>WiFi</button>
    <button class='tab' onclick='switchTab("clients",event)' data-i18n='tab_clients'>Clients</button>
    <button class='tab' onclick='switchTab("settings",event)' data-i18n='tab_settings'>Settings</button>
  </div>

  <div id='tab-wifi' class='tab-content active'>
    <div class='header-row'><h1 data-i18n='wifi_setup'>WiFi</h1><button class='refresh-btn' onclick='scan()' data-i18n='refresh'>Refresh</button></div>
    <div id='status-msg'></div>
    <div id='dns-msg' class='hint'></div>
    <div class='network-list' id='list'><div class='loading' data-i18n='scanning_networks'>Scanning...</div></div>
    <div class='form-group'><label data-i18n='ssid_label'>Network name</label><input type='text' id='ssid' data-i18n-ph='ssid_ph' placeholder='Network name'></div>
    <div class='form-group'><label data-i18n='password_label'>Password</label><input type='password' id='pwd' data-i18n-ph='pass_ph' placeholder='Password'></div>
    <button class='btn' onclick='connect()' data-i18n='connect_btn'>CONNECT</button>
  </div>

  <div id='tab-clients' class='tab-content'>
    <div class='header-row'><h1 data-i18n='tab_clients'>Clients</h1><button class='refresh-btn' onclick='loadClients()' data-i18n='refresh'>Refresh</button></div>
    <div class='hint' data-i18n='clients_hint'></div>
    <div id='client-list'><div class='loading' data-i18n='loading'>Loading...</div></div>
  </div>

  <div id='tab-settings' class='tab-content'>
    <h1 data-i18n='tab_settings'>Settings</h1>

    <h2 data-i18n='sec_ap'>Access point</h2>
    <div class='form-group'><label data-i18n='ap_name'>AP name (SSID)</label><input type='text' id='ssid-name'><div class='hint' style='margin:6px 0 0' data-i18n='ap_name_hint'></div></div>
    <button class='btn' onclick='saveSsid()' data-i18n='save_name_btn'>SAVE NAME</button>
    <div class='form-group' style='margin-top:14px'><label data-i18n='cur_ap_pass'>Current password</label><input type='text' id='current-pass' readonly></div>
    <div class='form-group'><label data-i18n='new_ap_pass'>New password</label><input type='text' id='new-pass' data-i18n-ph='new_pass_ph' placeholder='at least 8 characters'></div>
    <button class='btn' onclick='changePass()' data-i18n='change_pass_btn'>CHANGE PASSWORD</button>
    <div style='margin-top:8px'><button class='btn danger small' onclick='resetAP()' data-i18n='reset_btn'>RESET TO RANDOM</button></div>

    <h2 data-i18n='sec_panel'>Web panel access</h2>
    <div id='auth-state' class='hint'></div>
    <div class='row form-group'><div><label data-i18n='user_label'>User</label><input type='text' id='web-user'></div></div>
    <div class='form-group'><label data-i18n='panel_pass'>Password</label><input type='password' id='web-pass' data-i18n-ph='panel_pass_ph' placeholder='empty = no password'></div>
    <button class='btn' onclick='savePanelAuth()' data-i18n='save_auth_btn'>SAVE</button>

    <h2 data-i18n='sec_doh'>Default resolver</h2>
    <div class='hint' data-i18n='doh_hint'></div>
    <div class='form-group'><label data-i18n='resolver_url'>Resolver address</label><input type='text' id='doh-url'></div>
    <button class='btn' onclick='saveDoh()' data-i18n='save_resolver_btn'>SAVE RESOLVER</button>
    <div id='doh-state' class='hint' style='margin-top:10px'></div>
    <div id='doh-suggest' class='hint'></div>

    <h2 data-i18n='sec_radio'>Radio</h2>
    <div id='radio-state' class='hint'></div>
    <div class='form-group'><label data-i18n='channel_width'>Channel width</label>
      <select id='bw-sel'><option value='40' data-i18n-opt='bw40'>40 MHz (HT40)</option><option value='20' data-i18n-opt='bw20'>20 MHz (HT20)</option></select></div>
    <button class='btn' onclick='saveRadio()' data-i18n='apply_btn'>APPLY</button>

    <h2 data-i18n='sec_perdev'>Per-device DNS</h2>
    <div class='hint' data-i18n='perdev_hint'></div>
    <div class='form-group'><label data-i18n='device_mac'>Device MAC</label><input type='text' id='dr-mac' placeholder='aa:bb:cc:dd:ee:ff'></div>
    <div class='form-group'><label data-i18n='protocol'>Protocol</label>
      <select id='dr-mode'><option value='doh' data-i18n-opt='doh_opt'>DoH (https:// URL)</option><option value='dot' data-i18n-opt='dot_opt'>DoT (IP, port 853)</option><option value='dns' data-i18n-opt='dns_opt'>Plain DNS (IP, port 53)</option></select></div>
    <div class='form-group'><label data-i18n='preset_label'>Preset</label><select id='dr-preset'></select></div>
    <div class='form-group'><label data-i18n='resolver_addr'>Resolver address</label><input type='text' id='dr-addr'></div>
    <div class='hint' data-i18n='preset_note'></div>
    <button class='btn' onclick='addDnsRule()' data-i18n='save_rule_btn'>SAVE RULE</button>
    <div style='margin-top:8px'><button class='btn small' onclick='runDnsTest()' data-i18n='test_btn'>TEST ALL RESOLVERS</button></div>
    <div id='dr-list' style='margin-top:12px'></div>
    <div id='dr-msg' class='hint' style='margin-top:10px'></div>

    <h2 data-i18n='sec_leases'>Static leases</h2>
    <div class='hint' data-i18n='leases_hint'></div>
    <div class='row form-group'><div><label data-i18n='mac_label'>MAC</label><input type='text' id='lease-mac' placeholder='aa:bb:cc:dd:ee:ff'></div><div><label data-i18n='ip_label'>IP</label><input type='text' id='lease-ip' placeholder='192.168.4.150'></div></div>
    <button class='btn' onclick='addLease()' data-i18n='add_lease_btn'>ADD LEASE</button>
    <div id='lease-list' style='margin-top:12px'></div>
    <div id='lease-msg' class='hint' style='margin-top:10px'></div>

    <h2 data-i18n='sec_fwd'>Port forwarding</h2>
    <div class='hint' data-i18n='fwd_hint'></div>
    <div id='pm-note' class='hint'></div>
    <div class='row form-group'><div><label data-i18n='proto_label'>Protocol</label><select id='pm-proto'><option value='tcp'>TCP</option><option value='udp'>UDP</option></select></div><div><label data-i18n='ext_port'>Ext port</label><input type='text' id='pm-mport' placeholder='8080'></div></div>
    <div class='row form-group'><div><label data-i18n='target_ip'>Target IP</label><input type='text' id='pm-daddr' placeholder='192.168.4.150'></div><div><label data-i18n='target_port'>Target port</label><input type='text' id='pm-dport' placeholder='80'></div></div>
    <button class='btn' onclick='addPortmap()' data-i18n='add_fwd_btn'>ADD FORWARD</button>
    <div id='pm-list' style='margin-top:12px'></div>
    <div id='pm-msg' class='hint' style='margin-top:10px'></div>

    <h2 data-i18n='sec_apctl'>AP controls</h2>
    <div class='form-group'><label data-i18n='hidden_label'>Hide SSID</label>
      <select id='ap-hidden'><option value='0'>OFF</option><option value='1'>ON</option></select>
      <div class='hint' style='margin:6px 0 0' data-i18n='hidden_hint'></div></div>
    <div class='row form-group'>
      <div><label data-i18n='maxconn_label'>Max clients</label><input type='text' id='ap-maxconn'></div>
      <div><label data-i18n='txpower_label'>TX power</label><input type='text' id='ap-txpower'></div>
    </div>
    <div class='hint' data-i18n='txpower_hint'></div>
    <div class='hint' data-i18n='restart_note'></div>
    <button class='btn' onclick='saveApCfg()' data-i18n='save_apctl_btn'>APPLY AP SETTINGS</button>

    <h2 data-i18n='sec_acl'>Client allow-list</h2>
    <div class='hint' data-i18n='acl_hint'></div>
    <div id='acl-state' class='hint'></div>
    <div class='row form-group'><div><label data-i18n='mac_label'>MAC</label><input type='text' id='acl-mac' placeholder='aa:bb:cc:dd:ee:ff'></div></div>
    <button class='btn small' onclick='aclAdd()' data-i18n='acl_add_btn'>ADD MAC</button>
    <div style='margin-top:8px'><button class='btn small' onclick='aclToggle()' id='acl-toggle-btn'>ENFORCE</button></div>
    <div id='acl-list' style='margin-top:12px'></div>
    <div id='acl-msg' class='hint' style='margin-top:10px'></div>

    <h2 data-i18n='sec_policy'>Device ownership</h2>
    <div class='form-group'><label><input type='checkbox' id='pol-claim' style='width:auto;margin-right:6px'><span data-i18n='guest_claim_label'></span></label>
      <div class='hint' style='margin:6px 0 0' data-i18n='guest_claim_hint'></div></div>
    <div class='form-group'><label><input type='checkbox' id='pol-clrvis' style='width:auto;margin-right:6px'><span data-i18n='clear_visit_label'></span></label>
      <div class='hint' style='margin:6px 0 0' data-i18n='clear_visit_hint'></div></div>
    <button class='btn' onclick='saveDevPolicy()' data-i18n='save_btn'>SAVE</button>

    <h2 data-i18n='sec_fw'>Firmware update</h2>
    <div class='hint' style='margin:0 0 10px'><span data-i18n='fw_current'></span>
      <b id='fw-version'>-</b> <span class='mono' id='fw-slot'></span></div>

    <div class='form-group'><label data-i18n='ota_freq'></label>
      <select id='ota-hours'>
        <option value='0' data-i18n='ota_freq_off'>Off</option>
        <option value='6' data-i18n='ota_freq_6h'>Every 6 hours</option>
        <option value='12' data-i18n='ota_freq_12h'>Every 12 hours</option>
        <option value='24' data-i18n='ota_freq_24h'>Daily</option>
        <option value='168' data-i18n='ota_freq_7d'>Weekly</option>
      </select></div>
    <div class='form-group'><label><input type='checkbox' id='ota-auto' style='width:auto;margin-right:6px'><span data-i18n='ota_auto'></span></label>
      <div class='hint' style='margin:6px 0 0' data-i18n='ota_auto_hint'></div></div>
    <div class='form-group'><label data-i18n='ota_url_label'></label><input type='text' id='ota-url' placeholder='http://host/api/v1/repos/owner/repo/releases/latest'></div>
    <button class='btn' onclick='saveOtaCfg()' data-i18n='ota_save_btn'>SAVE SETTINGS</button>

    <div style='margin-top:14px;padding-top:12px;border-top:1px solid #e2e8f0'>
      <div id='ota-status' class='hint' style='margin:0 0 8px'></div>
      <progress id='ota-bar' max='100' value='0' style='display:none;width:100%;height:8px'></progress>
      <button class='btn' id='ota-check-btn' onclick='otaCheckNow()' data-i18n='ota_check_btn'>CHECK FOR UPDATES</button>
      <button class='btn danger' id='ota-install-btn' style='display:none' onclick='otaInstallNow()' data-i18n='ota_install_btn'>INSTALL</button>
      <div id='ota-msg' class='hint' style='margin:8px 0 0'></div>
    </div>

    <h2 data-i18n='sec_upload'>Manual upload</h2>
    <div class='form-group'><label data-i18n='fw_file'></label><input type='file' id='fw-file' accept='.bin'></div>
    <progress id='fw-bar' max='100' value='0' style='display:none;width:100%;height:8px'></progress>
    <button class='btn danger' id='fw-btn' onclick='otaUpload()' data-i18n='fw_upload_btn'>UPLOAD AND RESTART</button>
    <div class='hint' style='margin:8px 0 0' data-i18n='fw_hint'></div>
    <div class='hint' style='margin:8px 0 0' data-i18n='fw_ap_note'></div>
    <div id='fw-msg' class='hint' style='margin-top:8px'></div>

    <h2 data-i18n='sec_about'>About</h2>
    <div class='form-group'><label data-i18n='mdns_name'>mDNS name</label><input type='text' id='mdns-name'></div>
    <button class='btn' onclick='saveHostname()' data-i18n='save_mdns_btn'>SAVE NAME</button>
    <div id='settings-msg' class='hint' style='margin-top:10px'></div>
  </div>

  </div>
  <div class='footer'>
    <div data-i18n='footer_line'>EmbedWRT &middot; ESP32-S3 &middot; GPL v3</div>
    <div><a href='https://github.com/Svarkovsky/esp32-wifi-pocket' target='_blank'>based on esp32-wifi-pocket</a></div>
  </div>
</div>
<div id='modal' onclick='if(event.target===this)hideLogin()'>
  <div class='box'>
    <h3 data-i18n='login_title'>Administrator login</h3>
    <div class='form-group'><label data-i18n='login_user'>User</label><input type='text' id='lg-user'></div>
    <div class='form-group'><label data-i18n='login_pass'>Password</label><input type='password' id='lg-pass'></div>
    <div class='row'><div><button class='btn' onclick='doLogin()' data-i18n='login_submit'>LOG IN</button></div>
    <div><button class='btn' style='background:#e2e8f0;color:#475569' onclick='hideLogin()' data-i18n='login_cancel'>Cancel</button></div></div>
    <div class='err' id='lg-err'></div>
  </div>
</div>
<script>
var I18N={
en:{
 title:'EmbedWRT',subtitle:'WiFi NAT router &middot; DoH / DoT',
 tab_wifi:'WiFi',tab_clients:'Clients',tab_settings:'Settings',
 wifi_setup:'Upstream WiFi',refresh:'Refresh',scanning_networks:'Scanning...',
 ssid_label:'Network name',ssid_ph:'Network name',password_label:'Password',pass_ph:'Password',
 connect_btn:'CONNECT',
 checking:'Checking status...',connected_to:'Connected to:',not_connected:'Not connected',
 clients_hint:'Signal is measured at this device, i.e. how well the client reaches the repeater. Per-client traffic volume is not tracked by the WiFi driver.',
 sec_ap:'Access point',ap_name:'AP name (SSID)',ap_name_hint:'Changing this restarts WiFi: every client is dropped for a few seconds and the phone must rejoin. On iOS a new network name also means a new private MAC address, so MAC-based rules and leases must be re-added.',
 save_name_btn:'SAVE NAME',cur_ap_pass:'Current password',new_ap_pass:'New password',new_pass_ph:'at least 8 characters',
 change_pass_btn:'CHANGE PASSWORD',reset_btn:'RESET TO RANDOM',
 sec_panel:'Web panel access',user_label:'User',panel_pass:'Panel password',panel_pass_ph:'empty = no password (open)',
 save_auth_btn:'SAVE',auth_open:'No password set. This panel is reachable by anyone on the network.',auth_on:'Password is set.',
 sec_doh:'Default resolver',doh_hint:'Used by devices with no per-device rule below.',
 resolver_url:'Resolver address',save_resolver_btn:'SAVE RESOLVER',
 sec_radio:'Radio',channel_width:'Channel width',bw40:'40 MHz (HT40)',bw20:'20 MHz (HT20, better at range)',apply_btn:'APPLY',
 sec_perdev:'Per-device DNS',perdev_hint:'Leave empty to use the default resolver for every device.',
 device_mac:'Device MAC',protocol:'Protocol',doh_opt:'DoH (https:// URL)',dot_opt:'DoT (IP, port 853)',dns_opt:'Plain DNS (IP, port 53)',
 resolver_addr:'Resolver address',save_rule_btn:'SAVE RULE',test_btn:'TEST ALL RESOLVERS',preset_label:'Preset',preset_choose:'- pick a common resolver -',preset_cn:'Domestic (works here)',preset_foreign:'Foreign (blocked on this network)',preset_foreign_plain:'Foreign (reachable for plain DNS)',preset_note:'Foreign DoH and DoT are unreachable from this network: TCP 443 and 853 to them are filtered. Plain DNS to them does work. Pick a domestic one unless you know the path is open.',
 sec_leases:'Static leases',leases_hint:'Pick an address outside the dynamic pool. iOS "Private Wi-Fi Address" rotates the MAC, which breaks MAC-based rules.',
 mac_label:'MAC',ip_label:'IP',add_lease_btn:'ADD LEASE',
 sec_fwd:'Port forwarding',fwd_hint:'Reachable from the upstream network only. The external address is what this device holds on the upstream side, and that address is itself behind the router NAT.',
 proto_label:'Protocol',ext_port:'Ext port',target_ip:'Target IP',target_port:'Target port',add_fwd_btn:'ADD FORWARD',
 sec_apctl:'AP controls',hidden_label:'Hide SSID',hidden_hint:'The network stops broadcasting its name. Clients must be told the name to join, and hidden networks are not actually more private - the name is still visible in the traffic.',
 maxconn_label:'Max clients',txpower_label:'TX power (dBm)',txpower_hint:'Lowering this can reduce interference; range may suffer.',
 save_apctl_btn:'APPLY AP SETTINGS',restart_note:'Changing hide-SSID or the client limit restarts the radio, so all clients drop for a few seconds.',
 sec_acl:'Client allow-list',acl_hint:'NOT access control. ESP-IDF cannot refuse an association, so a disallowed client completes the handshake first and is then deauthenticated. It appears in the client list each time it retries. Treat this as a deterrent.',
 acl_state_on:'Allow-list is ENFORCED.',acl_state_off:'Allow-list is off; every client may join.',
 acl_add_btn:'ADD MAC',acl_enable_btn:'ENFORCE LIST',acl_disable_btn:'STOP ENFORCING',
 acl_empty:'No MACs allowed yet.',acl_my_mac:'Your MAC',
 sec_about:'About',mdns_name:'mDNS name',save_mdns_btn:'SAVE NAME',footer_line:'EmbedWRT &middot; ESP32-S3 &middot; GPL v3',
 loading:'Loading...',no_clients:'No clients',cfg_btn:'Settings',iot_label:'IoT device',iot_hint:'An IoT device can be managed by its owner without logging in.',owner_label:'Owner',owner_none:'(unowned)',save_dev_btn:'SAVE',claim_btn:'Claim',release_btn:'Release',sec_policy:'Device ownership',guest_claim_label:'Allow visitors to claim unowned IoT devices',guest_claim_hint:'A visitor can take an unowned IoT device without logging in, and release it again. Only unowned ones, so one visitor cannot take a device another already manages.',clear_visit_label:'Drop the IoT flag when that device opens the panel',clear_visit_hint:'Anything able to open a web UI is not a dumb IoT device. Only affects the device that visits.',claimable_hint:'Unowned - a visitor may claim this.',your_device:'Your device',guest_devices:'Devices you can manage',device_offline:'offline',
 sec_fw:'Firmware update',fw_current:'Installed version',fw_slot:'slot',fw_file:'Firmware file (.bin)',
 fw_hint:'Upload build/embedwrt.bin - the application image. The merged full-flash image will not work here.',
 fw_upload_btn:'UPLOAD AND RESTART',
 fw_confirm:'Write this firmware to the device? It will restart and every client will drop.',
 fw_uploading:'Uploading',fw_ok:'Firmware written. The device is restarting.',
 fw_wait:'Waiting for the device to come back',fw_relogin:'The device restarted. Log in again to check the new version.',
 fw_failed:'Update failed',fw_nofile:'Choose a firmware file first',
 fw_noback:'The device did not come back. Reload this page to check.',
 fw_ap_note:'The upload takes a minute over WiFi, and DNS and forwarding will stutter while it writes. The access point stays up until the restart.',
 sec_upload:'Manual upload',
 ota_freq:'Check for updates',ota_freq_off:'Off',ota_freq_6h:'Every 6 hours',ota_freq_12h:'Every 12 hours',ota_freq_24h:'Daily',ota_freq_7d:'Weekly',
 ota_auto:'Install new versions without asking',
 ota_auto_hint:'Off by default: a restart drops every client, so the device waits for you. With this on it installs as soon as it finds a newer release.',
 ota_url_label:'Release feed URL',ota_save_btn:'SAVE SETTINGS',
 ota_check_btn:'CHECK FOR UPDATES',ota_checking:'Checking',ota_uptodate:'Up to date',
 ota_available:'Version {v} is available.',ota_install_btn:'INSTALL AND RESTART',
 ota_downloading:'Downloading',ota_installing:'Written and verified; restarting',
 ota_lastcheck:'Last checked',ota_never:'never',ota_failed:'Update check failed',
 ota_ago_min:'{n} min ago',ota_ago_hour:'{n} h ago',ota_ago_day:'{n} d ago',
 ota_install_confirm:'Install the new firmware and restart? Every client will drop.',
 login_btn:'Log in',logout_btn:'Log out',login_title:'Administrator login',
 login_user:'User',login_pass:'Password',login_submit:'LOG IN',login_cancel:'Cancel',
 login_failed:'Wrong user or password',login_ok:'Signed in',
 guest_body:'Signed out. You can manage this device below, or log in as administrator.',
 guest_you:'Your address',
 guest_noident:'This address does not belong to a device on this network, so there is nothing to show. Log in as administrator for full access.',
 session_open:'No admin password is set, so the panel is open to anyone who can reach it.',lease_for:'Static lease for this device',dns_for:'DNS for this device',save_btn:'SAVE',remove_btn:'REMOVE',set_mark:'set',not_set:'not set',use_default_dns:'(none - uses the default resolver)',no_rules:'No rules',no_leases:'No static leases',no_forwards:'No rules',no_networks:'No networks',scan_failed:'Scan failed',failed_load:'Failed to load',
 active:'(active)',delete:'delete',uptime:'up',unknown:'unknown',
 confirm_lease:'Remove the lease for',confirm_rule:'Remove the DNS rule for',confirm_fwd:'Remove',
 enter_both:'Fill in all fields',rejected:'Rejected',saved:'Saved.',applied:'Applied.',failed:'Failed',
 already_connected:'Already connected to',enter_ssid:'Enter a network name',
 pass_short:'Password must be at least 8 characters',pass_changed:'Password changed. You may need to reconnect.',pass_failed:'Failed to change password.',
 reset_confirm:'Reset the AP password to a new random value? You will need to reconnect.',reset_done:'AP password reset. The page will reload.',reset_failed:'Failed to reset password.',
 testing:'Testing each resolver with a real query; this takes a few seconds per entry...',test_failed:'Test request failed',
 doh_mode_doh:'DoH',doh_mode_plain:'plaintext fallback',doh_mode_none:'off',doh_mode_idle:'idle (no lookup yet)',doh_mode_clock:'waiting for the clock',
 pool_free:'Addresses outside',pool_in_use:'are handed out dynamically.',
 lease_note:'The client picks it up on its next request.',
 fwd_external:'Reachable from the upstream network at',
 fwd_no_ext:'No upstream address yet.',
 no_pass_set:'No password set',
 enable_btn:'ENABLE',disable_btn:'DISABLE'
},
zh:{
 title:'EmbedWRT',subtitle:'WiFi 中继路由器 &middot; DoH / DoT',
 tab_wifi:'WiFi',tab_clients:'客户端',tab_settings:'设置',
 wifi_setup:'上级 WiFi',refresh:'刷新',scanning_networks:'正在扫描...',
 ssid_label:'网络名称',ssid_ph:'网络名称',password_label:'密码',pass_ph:'密码',
 connect_btn:'连 接',
 checking:'正在检查状态...',connected_to:'已连接到：',not_connected:'未连接',
 clients_hint:'这里显示的是本机测到的信号，即客户端到中继的连接质量。WiFi 驱动不统计每个客户端的流量。',
 sec_ap:'热点',ap_name:'热点名称（SSID）',ap_name_hint:'修改会重启 WiFi：所有客户端会断开几秒，手机需要重新加入。iOS 上换网络名还会换一个新的随机 MAC，所以按 MAC 的规则和租约都需要重新添加。',
 save_name_btn:'保存名称',cur_ap_pass:'当前密码',new_ap_pass:'新密码',new_pass_ph:'至少 8 个字符',
 change_pass_btn:'修改密码',reset_btn:'重置为随机密码',
 sec_panel:'管理面板访问',user_label:'用户名',panel_pass:'面板密码',panel_pass_ph:'留空 = 不设密码（开放）',
 save_auth_btn:'保存',auth_open:'未设置密码。局域网内任何人都能打开并修改本面板。',auth_on:'已设置密码。',
 sec_doh:'默认解析器',doh_hint:'未单独指定规则的设备使用这一项。',
 resolver_url:'解析器地址',save_resolver_btn:'保存解析器',
 sec_radio:'射频',channel_width:'信道宽度',bw40:'40 MHz (HT40)',bw20:'20 MHz (HT20，远距离更好)',apply_btn:'应用',
 sec_perdev:'按设备指定 DNS',perdev_hint:'留空表示所有设备都用上面的默认解析器。',
 device_mac:'设备 MAC',protocol:'协议',doh_opt:'DoH（https:// 地址）',dot_opt:'DoT（IP，端口 853）',dns_opt:'明文 DNS（IP，端口 53）',
 resolver_addr:'解析器地址',save_rule_btn:'保存规则',test_btn:'测试所有解析器',preset_label:'预设',preset_choose:'- 选择常用解析器 -',preset_cn:'国内（本网络可用）',preset_foreign:'国外（本网络不可达）',preset_foreign_plain:'国外（明文 DNS 可达）',preset_note:'国外的 DoH 和 DoT 在本网络不可达：到它们的 TCP 443 和 853 被拦截。国外明文 DNS 是通的。除非确认链路已开放，否则建议用国内。',
 sec_leases:'静态租约',leases_hint:'请选一个动态地址池之外的地址。iOS 的「私有 Wi-Fi 地址」会轮换 MAC，会让按 MAC 的规则失效。',
 mac_label:'MAC',ip_label:'IP',add_lease_btn:'添加租约',
 sec_fwd:'端口转发',fwd_hint:'只能从上级网络访问：外部地址是本机在上级网络的地址，而它本身还在路由器的 NAT 后面。',
 proto_label:'协议',ext_port:'外部端口',target_ip:'目标 IP',target_port:'目标端口',add_fwd_btn:'添加转发',
 sec_apctl:'热点控制',hidden_label:'隐藏 SSID',hidden_hint:'不再广播网络名。客户端必须知道名字才能加入；而且隐藏网络并不真的更私密——名字仍会出现在无线流量里。',
 maxconn_label:'最大客户端数',txpower_label:'发射功率（dBm）',txpower_hint:'降低可减少干扰，但覆盖距离可能变差。',
 save_apctl_btn:'应用热点设置',restart_note:'修改隐藏 SSID 或客户端上限会重启射频，所有客户端会断开几秒。',
 sec_acl:'客户端白名单',acl_hint:'这不是真正的接入控制。ESP-IDF 无法在关联时拒绝，所以不在名单上的客户端会先完成握手，然后被踢下线。它每次重试都会出现在客户端列表里。只能当作威慢手段。',
 acl_state_on:'白名单已生效。',acl_state_off:'白名单已关闭，任何客户端都能加入。',
 acl_add_btn:'添加 MAC',acl_enable_btn:'启用名单',acl_disable_btn:'停止过滤',
 acl_empty:'尚未添加任何 MAC。',acl_my_mac:'本机 MAC',
 sec_about:'关于',mdns_name:'mDNS 名称',save_mdns_btn:'保存名称',footer_line:'EmbedWRT &middot; ESP32-S3 &middot; GPL v3',
 loading:'加载中...',no_clients:'暂无客户端',cfg_btn:'设置',iot_label:'物联网设备',iot_hint:'标记为物联网设备后，其主人无需登录即可管理它。',owner_label:'主人',owner_none:'（未指派）',save_dev_btn:'保存',claim_btn:'认领',release_btn:'放弃',sec_policy:'设备归属',guest_claim_label:'允许访客认领无主的物联网设备',guest_claim_hint:'访客无需登录即可认领无主的物联网设备，也可以放弃。只限无主的，所以不会抢走别人已在管理的设备。',clear_visit_label:'该设备打开面板时自动取消其物联网标记',clear_visit_hint:'能自己打开网页的就不算哑设备。只影响访问面板的那台设备本身。',claimable_hint:'无主 - 访客可以认领。',your_device:'你的设备',guest_devices:'你可以管理的设备',device_offline:'离线',
 sec_fw:'固件更新',fw_current:'当前固件：',fw_slot:'槽位',fw_file:'固件文件（.bin）',
 fw_hint:'请上传 build/embedwrt.bin，即应用程序镜像。合并后的整片烧录镜像不能用于此处。',
 fw_upload_btn:'上传并重启',
 fw_confirm:'确定把该固件写入设备？设备会重启，所有客户端都会断开。',
 fw_uploading:'上传中',fw_ok:'固件已写入，设备正在重启。',
 fw_wait:'等待设备重新上线',fw_relogin:'设备已重启。请重新登录以确认新版本。',
 fw_failed:'更新失败',fw_nofile:'请先选择固件文件',
 fw_noback:'设备没有回应。请刷新本页查看。',
 fw_ap_note:'通过 WiFi 上传约需一分钟，写入期间 DNS 和转发会短暂卡顿。热点会保持到重启那一刻。',
 sec_upload:'手动上传',
 ota_freq:'检查更新频率',ota_freq_off:'关闭',ota_freq_6h:'每 6 小时',ota_freq_12h:'每 12 小时',ota_freq_24h:'每天',ota_freq_7d:'每周',
 ota_auto:'发现新版本直接安装，不询问',
 ota_auto_hint:'默认关闭：重启会踢掉所有客户端，所以由你决定时机。开启后会一发现新版本就自动安装。',
 ota_url_label:'发布源地址',ota_save_btn:'保存设置',
 ota_check_btn:'检查更新',ota_checking:'检查中',ota_uptodate:'已是最新',
 ota_available:'发现新版本 {v}。',ota_install_btn:'安装并重启',
 ota_downloading:'下载中',ota_installing:'已写入并校验通过，正在重启',
 ota_lastcheck:'上次检查',ota_never:'从未',ota_failed:'检查更新失败',
 ota_ago_min:'{n} 分钟前',ota_ago_hour:'{n} 小时前',ota_ago_day:'{n} 天前',
 ota_install_confirm:'确定安装新固件并重启？所有客户端都会断开。',
 login_btn:'登录',logout_btn:'退出登录',login_title:'管理员登录',
 login_user:'用户名',login_pass:'密码',login_submit:'登 录',login_cancel:'取消',
 login_failed:'用户名或密码错误',login_ok:'已登录',
 guest_body:'未登录。可在下方管理本机设备，或以管理员身份登录。',
 guest_you:'你的地址',
 guest_noident:'这个地址不属于本网络上的设备，因此没有可显示的内容。以管理员身份登录可获得完整权限。',
 session_open:'未设置管理员密码，能访问到本面板的人都可以操作。',lease_for:'该设备的静态租约',dns_for:'该设备的 DNS',save_btn:'保存',remove_btn:'移除',set_mark:'已设置',not_set:'未设置',use_default_dns:'（未设置 - 使用默认解析器）',no_rules:'暂无规则',no_leases:'暂无静态租约',no_forwards:'暂无规则',no_networks:'未发现网络',scan_failed:'扫描失败',failed_load:'加载失败',
 active:'（当前）',delete:'删除',uptime:'在线',unknown:'未知',
 confirm_lease:'确定删除该设备的静态租约：',confirm_rule:'确定删除该设备的 DNS 规则：',confirm_fwd:'确定删除',
 enter_both:'请填写完整',rejected:'被拒绝',saved:'已保存。',applied:'已应用。',failed:'失败',
 already_connected:'已经连接到',enter_ssid:'请输入网络名称',
 pass_short:'密码至少需要 8 个字符',pass_changed:'密码已修改，可能需要重新连接。',pass_failed:'修改密码失败。',
 reset_confirm:'确定把热点密码重置为新的随机值？之后需要重新连接。',reset_done:'热点密码已重置，页面将重新加载。',reset_failed:'重置密码失败。',
 testing:'正在用真实查询逐个测试解析器，每项可能需要几秒...',test_failed:'测试请求失败',
 doh_mode_doh:'DoH 加密',doh_mode_plain:'降级为明文',doh_mode_none:'未启用',doh_mode_idle:'空闲（尚无查询）',doh_mode_clock:'等待对时',
 pool_free:'动态地址池之外的',pool_in_use:'会被动态分配。',
 lease_note:'客户端下次请求时生效。',
 fwd_external:'可从上级网络访问：',
 fwd_no_ext:'还没有上级地址。',
 no_pass_set:'未设置密码',
 enable_btn:'启用',disable_btn:'停用'
}
};
var LANG='en';
try{var sv=localStorage.getItem('embedwrt_lang');if(sv){LANG=sv}else if((navigator.language||'').toLowerCase().indexOf('zh')===0){LANG='zh'}}catch(e){}
function t(k){var d=I18N[LANG]||I18N.en;var v=d[k];if(v===undefined){v=I18N.en[k]}return (v===undefined)?k:v}
function toggleLang(){LANG=(LANG==='zh')?'en':'zh';try{localStorage.setItem('embedwrt_lang',LANG)}catch(e){}applyLang()}
function applyLang(){
  document.documentElement.lang=(LANG==='zh')?'zh-CN':'en';
  var els=document.querySelectorAll('[data-i18n]');
  for(var i=0;i<els.length;i++){els[i].innerHTML=t(els[i].getAttribute('data-i18n'))}
  var ph=document.querySelectorAll('[data-i18n-ph]');
  for(var j=0;j<ph.length;j++){ph[j].placeholder=t(ph[j].getAttribute('data-i18n-ph'))}
  var op=document.querySelectorAll('[data-i18n-opt]');
  for(var k=0;k<op.length;k++){op[k].textContent=t(op[k].getAttribute('data-i18n-opt'))}
  document.getElementById('lang-btn').textContent=(LANG==='zh')?'EN':'中文';
  var ab=document.getElementById('auth-btn');
  if(ab && SESSION.auth_enabled){ ab.textContent=(SESSION.role==='admin')?t('logout_btn'):t('login_btn') }
  refreshActiveTab();
}
var DOH_STATE={doh:'doh_mode_doh',plain:'doh_mode_plain',off:'doh_mode_none',idle:'doh_mode_idle',clock:'doh_mode_clock'};
function dohText(m){return t(DOH_STATE[m]||'doh_mode_plain')}
function refreshActiveTab(){
  /* Role-aware: a guest must not issue admin requests at all. Without this
     guard applyLang() -> refreshActiveTab() -> init() fired /status and /scan
     for visitors, which came back 401 and filled the console with errors. */
  if(SESSION.role!=='admin'){return}
  if(document.getElementById('tab-wifi').classList.contains('active')){init()}
  else if(document.getElementById('tab-clients').classList.contains('active')){loadClients()}
  else{loadSettings(loadGen)}
}
function switchTab(tab,ev){
  var tabs=document.querySelectorAll('.tab'),cs=document.querySelectorAll('.tab-content');
  for(var i=0;i<tabs.length;i++){tabs[i].classList.remove('active')}
  for(var j=0;j<cs.length;j++){cs[j].classList.remove('active')}
  if(ev&&ev.target){ev.target.classList.add('active')}
  document.getElementById('tab-'+tab).classList.add('active');
  refreshActiveTab();
}
function initPresets(){
  wirePresets(document.getElementById('dr-mode'),
              document.getElementById('dr-preset'),
              document.getElementById('dr-addr'));
}
/* Sequential on purpose. Firing every section's request at once exceeds the
   httpd socket limit (max_open_sockets defaults to 7), and the panels for
   whatever loses the race render empty. Chaining keeps the socket count at one
   no matter how many sections are added later, and these requests are tiny on a
   LAN, so the limit should never be reached at all. */
/* Fetch several endpoints one at a time and collect the results in order.
   Serialised for the same reason loadSettings is: the httpd socket limit is 7
   and a page that opens several panels at once would otherwise reset some. */
function fetchSeq(urls){
  var out=[], p=Promise.resolve();
  urls.forEach(function(u,i){
    p=p.then(function(){
      return fetch(u).then(function(r){ return r.ok?r.json():null })
                    .then(function(d){ out[i]=d });
    });
  });
  return p.then(function(){ return out });
}
function runSequential(fns,gen){
  var p=Promise.resolve();
  fns.forEach(function(f){
    p=p.then(function(){
      if(gen!==undefined && gen!==loadGen){return}   /* superseded: stop */
      return f();
    });
  });
  return p;
}
function loadSettings(gen){
  return runSequential([loadSsid,loadAuth,loadDoh,loadRadio,loadApCfg,loadAcl,loadDevPolicy,
                        loadLeases,loadDnsRules,loadPortmaps,loadHostname,loadFwInfo],gen);
}
function init(){
  fetch('/status').then(function(r){return r.json()}).then(function(d){
    var msg=document.getElementById('status-msg');
    if(d.status==='connected'){
      msg.innerHTML=t('connected_to')+' <b>'+d.ssid+'</b>';
      msg.style.color='#15803d';msg.style.background='#f0fdf4';
    }else{
      msg.innerHTML=t('not_connected');
      msg.style.color='#b91c1c';msg.style.background='#fef2f2';
    }
    var dm=document.getElementById('dns-msg');
    var mode=d.doh||'';
    dm.innerHTML='DNS: '+dohText(mode)+(mode==='doh'?' ✓':'');
    scan();
  }).catch(function(){});
}
var lockSvg='<svg class="icon secure" viewBox="0 0 24 24"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"/></svg>';
var wifiSvg='<svg class="icon" viewBox="0 0 24 24"><path d="M1 9l2 2c4.97-4.97 13.03-4.97 18 0l2-2C16.93 2.93 7.08 2.93 1 9zm8 8l3 3 3-3c-1.65-1.66-4.34-1.66-6 0zm-4-4l2 2c2.76-2.76 7.24-2.76 10 0l2-2C15.14 9.14 8.87 9.14 5 13z"/></svg>';
var curSsid='';
function scan(){
  var lst=document.getElementById('list');lst.innerHTML='<div class="loading">'+t('scanning_networks')+'</div>';
  fetch('/scan').then(function(r){return r.json()}).then(function(data){
    lst.innerHTML='';
    if(!data.length){lst.innerHTML='<div class="loading">'+t('no_networks')+'</div>';return}
    data.forEach(function(net){
      var div=document.createElement('div');div.className='network-item';
      if(net.ssid===curSsid){div.style.background='#f0fdf4';div.style.borderLeft='3px solid #22c55e'}
      div.onclick=function(){document.getElementById('ssid').value=net.ssid};
      div.innerHTML="<div class='net-info'>"+net.ssid+(net.ssid===curSsid?' <b>'+t('active')+'</b>':'')+"</div><div class='net-icons'>"+(net.sec?lockSvg:'')+wifiSvg+"</div>";
      lst.appendChild(div);
    });
  }).catch(function(){lst.innerHTML='<div class="loading">'+t('scan_failed')+'</div>'});
}
function connect(){
  var s=document.getElementById('ssid').value,p=document.getElementById('pwd').value;
  if(!s){alert(t('enter_ssid'));return}
  if(s===curSsid){alert(t('already_connected')+' '+s);return}
  var btn=event.target;btn.innerText='...';btn.style.background='#94a3b8';
  fetch('/connect',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'ssid='+encodeURIComponent(s)+'&pass='+encodeURIComponent(p)})
  .then(function(){alert(t('saved')+' ')})
  .finally(function(){btn.innerText=t('connect_btn');btn.style.background='#3b82f6';setTimeout(init,3000)});
}
var CD_MODEKEY={doh:'doh_opt',dot:'dot_opt',dns:'dns_opt'};
function loadClients(){
  var box=document.getElementById('client-list');
  fetch('/api/clients').then(function(r){return r.json()}).then(function(d){
    if(!d.length){box.innerHTML='<div class="loading">'+t('no_clients')+'</div>';return}
    var h='<div class="network-list" style="max-height:none">';
    d.forEach(function(c){
      var r=c.rssi,col=(r>-60)?'#15803d':((r>-70)?'#b45309':'#b91c1c');
      var id=c.mac.replace(/:/g,'');
      /* The row is not clickable and the card is its SIBLING, not its child.
         Nested inside a clickable row, a click on a card button bubbled up to
         the row's handler, which toggled the card shut and cleared the
         reopen state before the save had even returned - so the card collapsed
         on every save and the result message went with it. */
      h+="<div style='border-bottom:1px solid #e2e8f0'>"
        +"<div class='network-item' style='cursor:default;border-bottom:none'>"
        +"<div style='flex:1;min-width:0'>"
        +"<div style='display:flex;justify-content:space-between;align-items:center;gap:8px'>"
        +"<span class='mono' style='font-size:12px;overflow:hidden;text-overflow:ellipsis'>"+c.mac+"</span>"
        +"<span style='color:"+col+";font-weight:700;font-size:13px;white-space:nowrap'>"+r+" dBm</span></div>"
        +"<div style='font-size:12px;color:#475569;margin-top:4px;overflow:hidden;text-overflow:ellipsis'>"+c.ip
        +(c.host?(" &middot; "+c.host):"")+" &middot; "+t('uptime')+" "+Math.floor(c.uptime/60)+"m</div>"
        +"</div>"
        +"<button class='refresh-btn' style='flex:0 0 auto;margin-left:10px' onclick='toggleClient(\""+id+"\")'>&#9881; "+t('cfg_btn')+"</button>"
        +"</div>"
        +"<div id='cd-"+id+"' data-mac='"+c.mac+"' data-ip='"+c.ip+"' style='display:none'></div>"
        +"</div>";
    });
    box.innerHTML=h+'</div>';
    /* Re-open and reload whichever card was expanded before, so a save does not
       silently collapse it and hide the result message. A block comment, not a
       line comment: the C literal is built line by line with the newlines
       removed, so a // comment would swallow the rest of the whole script. */
    if(openClientId){
      var el=document.getElementById('cd-'+openClientId);
      if(el){ el.style.display='block'; loadClientDetail(el,openClientId,keepMsg); }
      else { openClientId=null; }
    }
  }).catch(function(){box.innerHTML='<div class="loading">'+t('failed_load')+'</div>'});
}
var openClientId=null;
var keepMsg=null;
function toggleClient(id){
  var el=document.getElementById('cd-'+id);
  if(!el){return}
  if(el.style.display==='block'){openClientId=null;keepMsg=null;el.style.display='none';return}
  openClientId=id;keepMsg=null;
  el.style.display='block';
  loadClientDetail(el,id);
}
/* The lease + DNS half of a device card. Shared by the admin Clients tab and the
   guest view, so both edit a device the same way. */
function deviceEditHtml(id,mac,lease,rule,L,curIp){
  var suggest=curIp||'';
  if(lease){suggest=lease.ip}
  else if(L&&L.pool_known){
    var q=L.pool_last.split('.');
    suggest=q[0]+'.'+q[1]+'.'+q[2]+'.'+(parseInt(q[3],10)+1);
  }
  var h="";
  h+="<div style='padding:12px 14px;background:#f8fafc;border-top:1px solid #e2e8f0'>";
  h+="<label>"+t('lease_for')+" <span style='color:"+(lease?'#15803d':'#94a3b8')+"'>("
    +(lease?t('set_mark'):t('not_set'))+")</span></label>";
  h+="<div class='row'><div><input type='text' id='cd-ip-"+id+"' value='"+suggest+"'></div>"
    +"<div style='flex:0 0 auto'><button class='refresh-btn' onclick='cdSaveLease(\""+mac+"\",\""+id+"\")'>"+t('save_btn')+"</button></div>"
    +(lease?"<div style='flex:0 0 auto'><button class='refresh-btn' onclick='cdDelLease(\""+mac+"\",\""+id+"\")'>"+t('remove_btn')+"</button></div>":"")
    +"</div>";
  if(L&&L.pool_known){
    h+="<div class='hint' style='margin:6px 0 0'>"+t('pool_free')+" "+L.pool_first+"-"+L.pool_last+" "+t('pool_in_use')+"</div>";
  }
  h+="</div>";
  h+="<div style='padding:12px 14px;background:#f8fafc;border-top:1px solid #e2e8f0'>";
  h+="<label>"+t('dns_for')+" <span style='color:"+(rule?'#15803d':'#94a3b8')+"'>("
    +(rule?t('set_mark'):t('use_default_dns'))+")</span></label>";
  h+="<div class='row'><div><select id='cd-mode-"+id+"'>";
  ['doh','dot','dns'].forEach(function(m){
    h+="<option value='"+m+"'"+(rule&&rule.mode===m?' selected':'')+">"+t(CD_MODEKEY[m])+"</option>";
  });
  h+="</select></div></div>";
  h+="<div class='form-group' style='margin-top:8px'><label>"+t('preset_label')+"</label>"
    +"<select id='cd-preset-"+id+"'></select></div>";
  h+="<div class='row form-group'><div><input type='text' id='cd-addr-"+id+"' value='"
    +(rule?rule.addr:'')+"' placeholder='223.5.5.5'></div></div>";
  h+="<div class='row'><div><button class='refresh-btn' style='width:100%' onclick='cdSaveRule(\""+mac+"\",\""+id+"\")'>"+t('save_btn')+"</button></div>"
    +(rule?"<div><button class='refresh-btn' style='width:100%' onclick='cdDelRule(\""+mac+"\",\""+id+"\")'>"+t('remove_btn')+"</button></div>":"")
    +"</div>";
  h+="<div class='hint' style='margin:8px 0 0' id='cd-msg-"+id+"'></div>";
  h+="</div>";
  return h;
}
/* The admin-only half: IoT flag and owner. */
function deviceAttrHtml(id,mac,rec,clients){
  var h="<div style='padding:12px 14px;background:#f8fafc;border-top:1px solid #e2e8f0'>";
  h+="<label><input type='checkbox' id='cd-iot-"+id+"' style='width:auto;margin-right:6px'"
    +((rec&&rec.iot)?' checked':'')+">"+t('iot_label')+"</label>";
  h+="<div class='hint' style='margin:6px 0 0'>"+t('iot_hint')+"</div>";
  h+="<div class='form-group' style='margin:10px 0 0'><label>"+t('owner_label')+"</label><select id='cd-owner-"+id+"'>";
  h+="<option value=''>"+t('owner_none')+"</option>";
  (clients||[]).forEach(function(c){
    if(c.mac===mac){return}
    h+="<option value='"+c.mac+"'"+(rec&&rec.owner===c.mac?' selected':'')+">"
      +c.mac+(c.host?(' ('+c.host+')'):'')+"</option>";
  });
  h+="</select></div>";
  h+="<button class='refresh-btn' style='width:100%' onclick='cdSaveDevice(\""+mac+"\",\""+id+"\")'>"+t('save_dev_btn')+"</button>";
  h+="</div>";
  return h;
}
function loadClientDetail(el,id,msg)  {
  el.innerHTML='<div class="loading">'+t('loading')+'</div>';
  var mac=el.getAttribute('data-mac'),curIp=el.getAttribute('data-ip');
  fetchSeq(['/api/leases','/api/dnsrules','/api/devices','/api/clients']).then(function(res){
    var L=res[0]||{},R=res[1]||{},D=res[2]||{},C=res[3]||[];
    var lease=null;(L.leases||[]).forEach(function(x){if(x.mac===mac){lease=x}});
    var rule=null;(R.rules||[]).forEach(function(x){if(x.mac===mac){rule=x}});
    var rec=null;(D.devices||[]).forEach(function(x){if(x.mac===mac){rec=x}});
    el.innerHTML=deviceEditHtml(id,mac,lease,rule,L,curIp)+deviceAttrHtml(id,mac,rec,C);
    wirePresets(document.getElementById('cd-mode-'+id),
                document.getElementById('cd-preset-'+id),
                document.getElementById('cd-addr-'+id));
    if(msg){cdMsg(id,msg.ok,msg.txt)}
  }).catch(function(){el.innerHTML='<div class="loading">'+t('failed_load')+'</div>'});
}
function cdSaveDevice(mac,id){
  var rec=null,cb=document.getElementById('cd-iot-'+id);
  var iot=(cb&&cb.checked)?'1':'0';
  var owner=(document.getElementById('cd-owner-'+id)||{}).value||'';
  var m=document.getElementById('cd-msg-'+id);
  fetch('/device/set',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:'mac='+encodeURIComponent(mac)+'&iot='+iot+'&owner='+encodeURIComponent(owner)})
  .then(function(r){return r.text().then(function(x){
    if(m){m.innerHTML=r.ok?('<span style="color:#15803d">'+t('saved')+'</span>')
                         :('<span style="color:#b91c1c">'+t('rejected')+': '+x+'</span>')}
  })});
}
/* The guest's devices: its own entry, the IoT devices it owns, and - when
   claiming is enabled - unowned IoT devices it could take. Driven by /api/devices
   (which knows the claim flags and includes offline devices) unioned with
   /api/clients (which has the live hostname and address). */
function loadGuestView(msg){
  var box=document.getElementById('guest-devices');
  box.innerHTML='<div class="loading">'+t('loading')+'</div>';
  fetchSeq(['/api/devices','/api/clients','/api/leases','/api/dnsrules']).then(function(res){
    var D=res[0]||{},C=res[1]||[],L=res[2]||{},R=res[3]||{};
    var me=D.me||'';
    var rec={};(D.devices||[]).forEach(function(d){rec[d.mac]=d});
    var live={};C.forEach(function(c){live[c.mac]=c});
    var seen={},order=[];
    function add(m){if(m&&!seen[m]){seen[m]=1;order.push(m)}}
    /* This device first: it is the one the visitor came to configure. */
    add(me);
    (D.devices||[]).forEach(function(d){add(d.mac)});
    C.forEach(function(c){add(c.mac)});
    var gb=document.getElementById('guest-body');
    if(!order.length){
      /* No identity, so there is nothing below to manage. Hide the line that
         offers to manage it, or the two hints contradict each other. */
      if(gb){gb.style.display='none'}
      box.innerHTML='<div class="hint">'+t('guest_noident')+'</div>';
      return;
    }
    if(gb){gb.style.display='block'}
    var h="<h2>"+t('guest_devices')+"</h2>";
    order.forEach(function(mac){
      var id=mac.replace(/:/g,'');
      var d=rec[mac]||{};
      var c=live[mac];
      var isSelf=(mac===me);
      /* A device always may edit itself. It has no record in /api/devices
         unless it is flagged or owned, so d.mine alone leaves a plain guest
         looking at its own card with no form. The write guards agree: a caller
         may touch its own MAC. */
      var editable=isSelf||!!d.mine;
      var claimable=!!d.claimable;
      var lease=null;(L.leases||[]).forEach(function(x){if(x.mac===mac){lease=x}});
      var rule=null;(R.rules||[]).forEach(function(x){if(x.mac===mac){rule=x}});
      var head=(c&&c.host)?c.host:t('unknown');
      h+="<div style='border:1px solid #e2e8f0;border-radius:8px;margin-bottom:12px;overflow:hidden'>";
      h+="<div style='padding:10px 14px;background:#f8fafc;display:flex;align-items:center;gap:8px'>";
      h+="<div style='flex:1;min-width:0'>"
        +"<div style='display:flex;justify-content:space-between;align-items:center;gap:8px'>"
        +"<span class='mono' style='font-size:12px;overflow:hidden;text-overflow:ellipsis'>"+mac+"</span>"
        +"<span style='font-size:12px;white-space:nowrap;color:"+(c?'#15803d':'#94a3b8')+"'>"
        +(c?(c.ip||'?'):t('device_offline'))+"</span></div>"
        +"<div style='font-size:12px;color:#475569;margin-top:3px;overflow:hidden;text-overflow:ellipsis'>"+head
        +(isSelf?(' &middot; <b>'+t('your_device')+'</b>'):'')
        +(claimable?(' &middot; '+t('claimable_hint')):'')+"</div>"
        +"</div>";
      if(editable){
        h+="<button class='refresh-btn' style='flex:0 0 auto' onclick='toggleGuest(\""+id+"\")'>&#9881; "+t('cfg_btn')+"</button>";
      }else if(claimable){
        /* Claiming is one action, so it gets a button rather than a card. */
        h+="<button class='refresh-btn' style='flex:0 0 auto' onclick='aclClaim(\""+mac+"\")'>"+t('claim_btn')+"</button>";
      }
      h+="</div>";
      if(editable){
        /* The card is a SIBLING of the bar, not its child: nested inside a
           clickable bar, a click on a card button bubbles up and toggles the
           card shut. The admin client row is built this way for the same
           reason. */
        h+="<div id='cd-"+id+"' style='display:none'>";
        h+=deviceEditHtml(id,mac,lease,rule,L,c?c.ip:'');
        /* An owned IoT device: its holder may hand it back. */
        if(d.iot&&d.owner===me&&!isSelf){
          h+="<div style='padding:0 14px 12px;background:#f8fafc'>"
            +"<button class='refresh-btn' style='width:100%' onclick='aclClaim(\""+mac+"\")'>"
            +t('release_btn')+"</button></div>";
        }
        h+="</div>";
      }
      h+="</div>";
    });
    box.innerHTML=h;
    order.forEach(function(mac){
      var id=mac.replace(/:/g,'');
      var ms=document.getElementById('cd-mode-'+id);
      if(ms){wirePresets(ms,document.getElementById('cd-preset-'+id),
                         document.getElementById('cd-addr-'+id))}
    });
    /* Re-open and reload whichever card was expanded before, so a save does not
       silently collapse it and hide the result message. */
    if(openGuestId){
      var el=document.getElementById('cd-'+openGuestId);
      if(el){
        el.style.display='block';
        if(msg){cdMsg(openGuestId,msg.ok,msg.txt)}
      }else{
        openGuestId=null;
      }
    }
  }).catch(function(){box.innerHTML='<div class="loading">'+t('failed_load')+'</div>'});
}
var openGuestId=null;
function toggleGuest(id){
  var el=document.getElementById('cd-'+id);
  if(!el){return}
  if(el.style.display==='block'){openGuestId=null;el.style.display='none';return}
  openGuestId=id;
  el.style.display='block';
}
/* A device card is drawn in two places - the admin Clients tab and the guest
   view. A save has to re-render whichever one is on screen; refreshing the other
   writes the result into hidden DOM and the user sees nothing at all. */
function isGuestView(){
  return document.getElementById('guest-view').style.display!=='none';
}
function refreshDeviceView(id,msg){
  if(isGuestView()){openGuestId=id;loadGuestView(msg);return}
  openClientId=id;keepMsg=msg;loadClients();
}
function cdMsg(id,ok,txt){
  var m=document.getElementById('cd-msg-'+id);
  if(m){m.innerHTML='<span style="color:'+(ok?'#15803d':'#b91c1c')+'">'+(ok?t('saved'):t('rejected')+': '+txt)+'</span>'}
}
function cdSaveLease(mac,id){
  var ip=document.getElementById('cd-ip-'+id).value.trim();
  if(!ip){keepMsg={ok:false,txt:t('enter_both')};cdMsg(id,false,t('enter_both'));return}
  fetch('/lease/add',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)+'&ip='+encodeURIComponent(ip)})
  .then(function(r){return r.text().then(function(x){
    refreshDeviceView(id,{ok:r.ok,txt:x});   /* reopens the card and shows x */
    loadLeases();
  })});
}
function cdDelLease(mac,id){
  if(!confirm(t('confirm_lease')+' '+mac+' ?')){return}
  fetch('/lease/del',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)})
  .then(function(){refreshDeviceView(id);loadLeases()});
}
function cdSaveRule(mac,id){
  var mode=document.getElementById('cd-mode-'+id).value;
  var addr=document.getElementById('cd-addr-'+id).value.trim();
  if(!addr){keepMsg={ok:false,txt:t('enter_both')};cdMsg(id,false,t('enter_both'));return}
  fetch('/dnsrule/set',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)+'&mode='+mode+'&addr='+encodeURIComponent(addr)})
  .then(function(r){return r.text().then(function(x){
    refreshDeviceView(id,{ok:r.ok,txt:x});
    loadDnsRules();
  })});
}
function cdDelRule(mac,id){
  if(!confirm(t('confirm_rule')+' '+mac+' ?')){return}
  fetch('/dnsrule/del',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)})
  .then(function(){refreshDeviceView(id);loadDnsRules()});
}
function loadSsid(){return fetch('/api/ssid').then(function(r){return r.json()}).then(function(d){document.getElementById('ssid-name').value=d.ssid}).catch(function(){})}
function saveSsid(){
  var v=document.getElementById('ssid-name').value.trim();
  if(!v){alert(t('enter_both'));return}
  var btn=event.target;btn.innerText='...';
  fetch('/setssid',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'ssid='+encodeURIComponent(v)})
  .then(function(r){return r.text().then(function(x){
    document.getElementById('settings-msg').innerHTML=r.ok?t('saved'):(t('rejected')+': '+x);
  })})
  .finally(function(){btn.innerText=t('save_name_btn')});
}
function loadAuth(){
  return fetch('/api/webauth').then(function(r){return r.json()}).then(function(d){
    document.getElementById('web-user').value=d.user;
    document.getElementById('auth-state').innerHTML=d.enabled?t('auth_on'):('<b>'+t('auth_open')+'</b>');
    document.getElementById('auth-state').style.color=d.enabled?'#15803d':'#b91c1c';
  }).catch(function(){});
}
function savePanelAuth(){
  var u=document.getElementById('web-user').value.trim(),p=document.getElementById('web-pass').value;
  var m=document.getElementById('settings-msg');
  fetch('/setwebauth',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'user='+encodeURIComponent(u)+'&pass='+encodeURIComponent(p)})
  .then(function(r){return r.text().then(function(x){m.innerHTML=r.ok?t('saved'):(t('rejected')+': '+x)});
  }).finally(function(){document.getElementById('web-pass').value='';loadAuth()});
}
function loadDoh(){
  return fetch('/api/dohurl').then(function(r){return r.json()}).then(function(d){
    document.getElementById('doh-url').value=d.url;
    var s=document.getElementById('doh-state');
    s.innerHTML=t('sec_doh')+': <b>'+dohText(d.mode)+'</b>';
    s.style.color=(d.mode==='doh')?'#15803d':((d.mode==='idle')?'#64748b':'#b45309');
    document.getElementById('doh-suggest').innerHTML="CN: <b>223.5.5.5</b> / <b>dns.alidns.com</b> / <b>1.12.12.12</b> / <b>doh.pub</b><br>1.1.1.1 / 8.8.8.8 / 9.9.9.9";
  }).catch(function(){});
}
function saveDoh(){
  var u=document.getElementById('doh-url').value.trim();
  if(u.indexOf('https://')!==0){alert('https://');return}
  var btn=event.target;btn.innerText='...';
  fetch('/setdohurl',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'url='+encodeURIComponent(u)})
  .then(function(r){document.getElementById('settings-msg').innerHTML=r.ok?t('saved'):t('rejected')})
  .finally(function(){btn.innerText=t('save_resolver_btn');loadDoh()});
}
function loadRadio(){
  return fetch('/api/radio').then(function(r){return r.json()}).then(function(d){
    document.getElementById('bw-sel').value=(d.bw==='HT20')?'20':'40';
    document.getElementById('radio-state').innerHTML=d.country+' &middot; CH '+d.ch_min+'-'+d.ch_max+' &middot; <b>'+d.txpower_dbm+' dBm</b>';
  }).catch(function(){});
}
function saveRadio(){
  var bw=document.getElementById('bw-sel').value;
  var btn=event.target;btn.innerText='...';
  fetch('/setradio',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'bw='+bw})
  .then(function(r){document.getElementById('settings-msg').innerHTML=r.ok?t('applied'):t('failed')})
  .finally(function(){btn.innerText=t('apply_btn');loadRadio()});
}
var DNS_PRESETS={
 doh:[
  {cn:1,name:'\u963f\u91cc 223.5.5.5',addr:'https://223.5.5.5/dns-query'},
  {cn:1,name:'\u963f\u91cc dns.alidns.com',addr:'https://dns.alidns.com/dns-query'},
  {cn:1,name:'\u817e\u8baf 1.12.12.12',addr:'https://1.12.12.12/dns-query'},
  {cn:1,name:'\u817e\u8baf doh.pub',addr:'https://doh.pub/dns-query'},
  {cn:0,name:'Cloudflare 1.1.1.1',addr:'https://1.1.1.1/dns-query'},
  {cn:0,name:'Google dns.google',addr:'https://dns.google/dns-query'},
  {cn:0,name:'Quad9 9.9.9.9',addr:'https://9.9.9.9/dns-query'}
 ],
 dot:[
  {cn:1,name:'\u963f\u91cc 223.5.5.5',addr:'223.5.5.5'},
  {cn:1,name:'\u963f\u91cc 223.6.6.6',addr:'223.6.6.6'},
  {cn:1,name:'\u817e\u8baf 1.12.12.12',addr:'1.12.12.12'},
  {cn:1,name:'\u817e\u8baf 120.53.53.53',addr:'120.53.53.53'},
  {cn:0,name:'Cloudflare 1.1.1.1',addr:'1.1.1.1'},
  {cn:0,name:'Google 8.8.8.8',addr:'8.8.8.8'},
  {cn:0,name:'Quad9 9.9.9.9',addr:'9.9.9.9'}
 ],
 dns:[
  {cn:1,name:'\u963f\u91cc 223.5.5.5',addr:'223.5.5.5'},
  {cn:1,name:'\u963f\u91cc 223.6.6.6',addr:'223.6.6.6'},
  {cn:1,name:'DNSPod 119.29.29.29',addr:'119.29.29.29'},
  {cn:1,name:'114DNS 114.114.114.114',addr:'114.114.114.114'},
  {cn:1,name:'\u767e\u5ea6 180.76.76.76',addr:'180.76.76.76'},
  {cn:0,name:'Cloudflare 1.1.1.1',addr:'1.1.1.1'},
  {cn:0,name:'Google 8.8.8.8',addr:'8.8.8.8'}
 ]
};
/* Rebuild a preset dropdown for the given protocol. Grouped, and the foreign
   group is labelled as unreachable here - verified by measurement, not assumed:
   TCP 443 and 853 to those addresses are filtered on this network while plain
   DNS to them passes. */
function fillPresets(sel,mode){
  if(!sel){return}
  var list=DNS_PRESETS[mode]||[];
  var h="<option value=''>"+t('preset_choose')+"</option>";
  var groups={1:[],0:[]};
  list.forEach(function(p){groups[p.cn].push(p)});
  /* Plain DNS to foreign servers is NOT filtered - only TCP 443 and 853 are - so
     the foreign group must not claim "unreachable" in that mode or it would steer
     the user away from servers that work. */
  var foreignKey=(mode==='dns')?'preset_foreign_plain':'preset_foreign';
  [[1,'preset_cn'],[0,foreignKey]].forEach(function(g){
    if(!groups[g[0]].length){return}
    h+="<optgroup label='"+t(g[1])+"'>";
    groups[g[0]].forEach(function(p){
      h+="<option value='"+p.addr+"'>"+p.name+"</option>";
    });
    h+="</optgroup>";
  });
  sel.innerHTML=h;
}
/* Wire a mode select, a preset select and an address input together. */
function wirePresets(modeSel,presetSel,addrInput){
  if(!modeSel||!presetSel||!addrInput){return}
  function sync(){ fillPresets(presetSel,modeSel.value) }
  modeSel.addEventListener('change',function(){ sync() });
  presetSel.addEventListener('change',function(){
    if(presetSel.value){ addrInput.value=presetSel.value }
  });
  sync();
}
function loadDnsRules(){
  var box=document.getElementById('dr-list');
  return fetch('/api/dnsrules').then(function(r){return r.json()}).then(function(d){
    if(!d.rules.length){box.innerHTML='<div class="loading">'+t('no_rules')+'</div>';return}
    var h='<div class="network-list" style="max-height:none">';
    d.rules.forEach(function(r){
      h+="<div class='network-item' style='cursor:default'><div style='display:flex;justify-content:space-between;align-items:center;width:100%'>"
        +"<span class='mono' style='font-size:11px'><b>"+r.mode+"</b> "+r.addr+"<br><span style='color:#64748b'>"+r.mac+"</span></span>"
        +"<button class='refresh-btn' onclick='delDnsRule(\""+r.mac+"\")'>"+t('delete')+"</button></div></div>";
    });
    box.innerHTML=h+'</div>';
  }).catch(function(){box.innerHTML='<div class="loading">'+t('failed_load')+'</div>'});
}
function addDnsRule(){
  var mac=document.getElementById('dr-mac').value.trim(),mode=document.getElementById('dr-mode').value,addr=document.getElementById('dr-addr').value.trim();
  var m=document.getElementById('dr-msg');
  if(!mac||!addr){m.innerHTML='<span style="color:#b45309">'+t('enter_both')+'</span>';return}
  fetch('/dnsrule/set',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)+'&mode='+mode+'&addr='+encodeURIComponent(addr)})
  .then(function(r){return r.text().then(function(x){
    m.innerHTML=r.ok?('<span style="color:#15803d">'+t('saved')+'</span>'):('<span style="color:#b91c1c">'+t('rejected')+': '+x+'</span>');
    if(r.ok){document.getElementById('dr-mac').value='';document.getElementById('dr-addr').value=''}
    loadDnsRules();
  })});
}
function delDnsRule(mac){
  if(!confirm(t('confirm_rule')+' '+mac+' ?')){return}
  fetch('/dnsrule/del',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)}).then(function(){loadDnsRules()});
}
function runDnsTest(){
  var m=document.getElementById('dr-msg');
  m.innerHTML='<span style="color:#64748b">'+t('testing')+'</span>';
  fetch('/api/dnstest').then(function(r){return r.json()}).then(function(d){
    var h="<div class='testout'><b>default</b> "+d.default.mode+' '+d.default.addr+'<br>&nbsp;&nbsp;'+d.default.result+'<br>';
    d.rules.forEach(function(r){h+='<b>'+r.mac+'</b> '+r.mode+' '+r.addr+'<br>&nbsp;&nbsp;'+r.result+'<br>'});
    m.innerHTML=h+'</div>';
  }).catch(function(){m.innerHTML='<span style="color:#b91c1c">'+t('test_failed')+'</span>'});
}
function loadLeases(){
  var box=document.getElementById('lease-list');
  return fetch('/api/leases').then(function(r){return r.json()}).then(function(d){
    document.getElementById('lease-msg').innerHTML=d.pool_known?(t('pool_free')+' <b>'+d.pool_first+'-'+d.pool_last+'</b> '+t('pool_in_use')):'';
    if(!d.leases.length){box.innerHTML='<div class="loading">'+t('no_leases')+'</div>';return}
    var h='<div class="network-list" style="max-height:none">';
    d.leases.forEach(function(l){
      h+="<div class='network-item' style='cursor:default'><div style='display:flex;justify-content:space-between;align-items:center;width:100%'>"
        +"<span class='mono' style='font-size:12px'><b>"+l.ip+"</b> &larr; "+l.mac+"</span>"
        +"<button class='refresh-btn' onclick='delLease(\""+l.mac+"\")'>"+t('delete')+"</button></div></div>";
    });
    box.innerHTML=h+'</div>';
  }).catch(function(){box.innerHTML='<div class="loading">'+t('failed_load')+'</div>'});
}
function addLease(){
  var mac=document.getElementById('lease-mac').value.trim(),ip=document.getElementById('lease-ip').value.trim();
  var m=document.getElementById('lease-msg');
  if(!mac||!ip){m.innerHTML='<span style="color:#b45309">'+t('enter_both')+'</span>';return}
  fetch('/lease/add',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)+'&ip='+encodeURIComponent(ip)})
  .then(function(r){return r.text().then(function(x){
    m.innerHTML=r.ok?('<span style="color:#15803d">'+t('saved')+' '+t('lease_note')+'</span>'):('<span style="color:#b91c1c">'+t('rejected')+': '+x+'</span>');
    if(r.ok){document.getElementById('lease-mac').value='';document.getElementById('lease-ip').value=''}
    loadLeases();
  })});
}
function delLease(mac){
  if(!confirm(t('confirm_lease')+' '+mac+' ?')){return}
  fetch('/lease/del',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)}).then(function(){loadLeases()});
}
function loadPortmaps(){
  var box=document.getElementById('pm-list');
  return fetch('/api/portmaps').then(function(r){return r.json()}).then(function(d){
    document.getElementById('pm-note').innerHTML=d.external?(t('fwd_external')+' <b>'+d.external+'</b>'):t('fwd_no_ext');
    if(!d.rules.length){box.innerHTML='<div class="loading">'+t('no_forwards')+'</div>';return}
    var h='<div class="network-list" style="max-height:none">';
    d.rules.forEach(function(r){
      h+="<div class='network-item' style='cursor:default'><div style='display:flex;justify-content:space-between;align-items:center;width:100%'>"
        +"<span class='mono' style='font-size:12px'><b>"+r.proto+' '+r.mport+"</b> &rarr; "+r.daddr+':'+r.dport+"</span>"
        +"<button class='refresh-btn' onclick='delPortmap(\""+r.proto+"\","+r.mport+")'>"+t('delete')+"</button></div></div>";
    });
    box.innerHTML=h+'</div>';
  }).catch(function(){box.innerHTML='<div class="loading">'+t('failed_load')+'</div>'});
}
function addPortmap(){
  var p=document.getElementById('pm-proto').value,mp=document.getElementById('pm-mport').value.trim();
  var da=document.getElementById('pm-daddr').value.trim(),dp=document.getElementById('pm-dport').value.trim();
  var m=document.getElementById('pm-msg');
  if(!mp||!da||!dp){m.innerHTML='<span style="color:#b45309">'+t('enter_both')+'</span>';return}
  fetch('/portmap/add',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'proto='+p+'&mport='+encodeURIComponent(mp)+'&daddr='+encodeURIComponent(da)+'&dport='+encodeURIComponent(dp)})
  .then(function(r){return r.text().then(function(x){
    m.innerHTML=r.ok?('<span style="color:#15803d">'+t('saved')+'</span>'):('<span style="color:#b91c1c">'+t('rejected')+': '+x+'</span>');
    if(r.ok){document.getElementById('pm-mport').value='';document.getElementById('pm-daddr').value='';document.getElementById('pm-dport').value=''}
    loadPortmaps();
  })});
}
function delPortmap(proto,mport){
  if(!confirm(t('confirm_fwd')+' '+proto+' '+mport+' ?')){return}
  fetch('/portmap/del',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'proto='+proto+'&mport='+mport}).then(function(){loadPortmaps()});
}
function loadApCfg(){
  return fetch('/api/apcfg').then(function(r){return r.json()}).then(function(d){
    document.getElementById('ap-hidden').value=d.hidden?'1':'0';
    document.getElementById('ap-maxconn').value=d.maxconn;
    document.getElementById('ap-txpower').value=d.txpower_dbm;
  }).catch(function(){});
}
function saveApCfg(){
  var h=document.getElementById('ap-hidden').value;
  var c=document.getElementById('ap-maxconn').value.trim();
  var p=document.getElementById('ap-txpower').value.trim();
  var m=document.getElementById('settings-msg');
  if(!c||!p){m.innerHTML='<span style="color:#b45309">'+t('enter_both')+'</span>';return}
  var btn=event.target;btn.innerText='...';
  fetch('/setapcfg',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'hidden='+h+'&maxconn='+encodeURIComponent(c)+'&txpower='+encodeURIComponent(p)})
  .then(function(r){return r.text().then(function(x){m.innerHTML=r.ok?t('applied'):(t('rejected')+': '+x)})})
  .finally(function(){btn.innerText=t('save_apctl_btn');loadApCfg()});
}
function loadDevPolicy(){
  return fetch('/api/devices').then(function(r){return r.json()}).then(function(d){
    document.getElementById('pol-claim').checked=!!d.guest_claim;
    document.getElementById('pol-clrvis').checked=!!d.clear_on_visit;
  }).catch(function(){});
}
function saveDevPolicy(){
  var m=document.getElementById('settings-msg');
  var c=document.getElementById('pol-claim').checked?'1':'0';
  var v=document.getElementById('pol-clrvis').checked?'1':'0';
  fetch('/setdevpolicy',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:'claim='+c+'&clearvisit='+v})
  .then(function(r){ m.innerHTML=r.ok?t('saved'):t('failed'); loadDevPolicy() })
  .catch(function(){ m.innerHTML=t('failed') });
}
function aclClaim(mac){
  var id=mac.replace(/:/g,'');
  fetch('/claim',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:'mac='+encodeURIComponent(mac)})
  .then(function(r){ return r.text().then(function(x){
    if(!r.ok){ alert(t('rejected')+': '+x) }
    /* Claiming makes the device editable, so open its card and say so. A
       release leaves it claimable with no card, where there is nowhere to put
       the message - the row changing back is the feedback. */
    openGuestId=id;
    loadGuestView(r.ok?{ok:true,txt:t('saved')}:null);
  }) });
}
function loadAcl(){
  var box=document.getElementById('acl-list');
  return fetch('/api/acl').then(function(r){return r.json()}).then(function(d){
    var st=document.getElementById('acl-state');
    st.innerHTML=d.enabled?('<b>'+t('acl_state_on')+'</b>'):t('acl_state_off');
    st.style.color=d.enabled?'#b45309':'#64748b';
    document.getElementById('acl-toggle-btn').innerHTML=d.enabled?t('acl_disable_btn'):t('acl_enable_btn');
    document.getElementById('acl-toggle-btn').className='btn small'+(d.enabled?' danger':'');
    if(!d.macs.length){box.innerHTML='<div class="loading">'+t('acl_empty')+'</div>';return}
    var h='<div class="network-list" style="max-height:none">';
    d.macs.forEach(function(m){
      h+="<div class='network-item' style='cursor:default'><div style='display:flex;justify-content:space-between;align-items:center;width:100%'>"
        +"<span class='mono' style='font-size:12px'>"+m+"</span>"
        +"<button class='refresh-btn' onclick='aclDel(\""+m+"\")'>"+t('delete')+"</button></div></div>";
    });
    box.innerHTML=h+'</div>';
  }).catch(function(){box.innerHTML='<div class="loading">'+t('failed_load')+'</div>'});
}
function aclAdd(){
  var mac=document.getElementById('acl-mac').value.trim(),m=document.getElementById('acl-msg');
  if(!mac){m.innerHTML='<span style="color:#b45309">'+t('enter_both')+'</span>';return}
  fetch('/acl/add',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)})
  .then(function(r){return r.text().then(function(x){
    m.innerHTML=r.ok?('<span style="color:#15803d">'+t('saved')+'</span>'):('<span style="color:#b91c1c">'+t('rejected')+': '+x+'</span>');
    if(r.ok){document.getElementById('acl-mac').value=''}
    loadAcl();
  })});
}
function aclDel(mac){
  fetch('/acl/del',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)}).then(function(){loadAcl()});
}
function aclToggle(){
  fetch('/api/acl').then(function(r){return r.json()}).then(function(d){
    var on=d.enabled?'0':'1',m=document.getElementById('acl-msg');
    fetch('/acl/enable',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'on='+on})
    .then(function(r){return r.text().then(function(x){
      m.innerHTML=r.ok?('<span style="color:#15803d">'+t('saved')+'</span>'):('<span style="color:#b91c1c">'+t('rejected')+': '+x+'</span>');
      loadAcl();
    })});
  });
}
function loadHostname(){return fetch('/api/hostname').then(function(r){return r.json()}).then(function(d){document.getElementById('mdns-name').value=d.hostname}).catch(function(){})}
function saveHostname(){
  var v=document.getElementById('mdns-name').value.trim();
  if(!v){alert(t('enter_both'));return}
  var btn=event.target;btn.innerText='...';
  fetch('/sethostname',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'hostname='+encodeURIComponent(v)})
  .then(function(r){return r.text().then(function(x){document.getElementById('settings-msg').innerHTML=r.ok?t('saved'):(t('rejected')+': '+x)})})
  .finally(function(){btn.innerText=t('save_mdns_btn')});
}
/* Installed build, and which OTA slot it is running from. The slot is what tells
   you an upload actually switched slots rather than silently doing nothing. */
/* Substitutes {name} placeholders. Applied to the result of t() rather than
   wrapped around it, so the generator still sees an ordinary lookup call and
   checks the key exists in both dictionaries. (Wrapping would hide the key from
   that scan, and the key check does not strip comments, so do not spell a
   literal lookup call out in prose either - it gets counted as a reference.) */
function sub(s,vars){
  if(!vars){return s}
  for(var p in vars){s=s.split('{'+p+'}').join(vars[p])}
  return s;
}
/* The device only ever sends fixed strings here, so this is belt and braces;
   it costs nothing and keeps the rule "never interpolate a reply into HTML"
   from depending on that staying true. */
function esc(s){
  return String(s==null?'':s)
    .split('&').join('&amp;')
    .split('<').join('&lt;')
    .split('>').join('&gt;');
}
function agoText(secs){
  if(!secs||secs<=0){return t('ota_never')}
  if(secs<3600){return sub(t('ota_ago_min'),{n:Math.max(1,Math.round(secs/60))})}
  if(secs<86400){return sub(t('ota_ago_hour'),{n:Math.round(secs/3600)})}
  return sub(t('ota_ago_day'),{n:Math.round(secs/86400)});
}
/* One request feeds the whole firmware block: version, slot, settings and the
   update state. */
function loadUpdateInfo(){
  return fetch('/api/update').then(function(r){return r.json()}).then(function(d){
    var v=document.getElementById('fw-version');
    if(v){v.textContent=(d.running||'?')}
    var s=document.getElementById('fw-slot');
    if(s){s.textContent=(d.slot?t('fw_slot')+' '+d.slot:'')}
    var h=document.getElementById('ota-hours');
    if(h){h.value=String(d.interval_hours)}
    var a=document.getElementById('ota-auto');
    if(a){a.checked=!!d.auto_install}
    var u=document.getElementById('ota-url');
    /* Never overwrite what the user is in the middle of typing. */
    if(u&&document.activeElement!==u){u.value=d.url||''}
    renderOtaState(d);
  }).catch(function(){});
}
function renderOtaState(d){
  var st=document.getElementById('ota-status');
  var bar=document.getElementById('ota-bar');
  var inst=document.getElementById('ota-install-btn');
  var btn=document.getElementById('ota-check-btn');
  if(!st){return}
  var line=t('ota_lastcheck')+': '+agoText(d.last_check_ago);
  var busy=(d.state==='checking'||d.state==='downloading'||d.state==='installing');
  if(btn){btn.disabled=busy}
  if(inst){inst.style.display=(d.state==='available')?'inline-block':'none'}
  if(bar){
    var show=(d.state==='downloading'||d.state==='installing');
    bar.style.display=show?'block':'none';
    bar.value=d.progress||0;
  }
  if(d.state==='checking'){st.innerHTML='<span style="color:#64748b">'+t('ota_checking')+'...</span>'}
  else if(d.state==='downloading'){st.innerHTML='<span style="color:#1d4ed8">'+t('ota_downloading')+' '+(d.progress||0)+'%</span>'}
  else if(d.state==='installing'){st.innerHTML='<span style="color:#b45309">'+t('ota_installing')+'</span>'}
  else if(d.state==='available'){st.innerHTML='<span style="color:#15803d"><b>'+sub(t('ota_available'),{v:d.latest})+'</b></span>'}
  else if(d.state==='uptodate'){st.innerHTML='<span style="color:#15803d">'+t('ota_uptodate')+'</span>'}
  else if(d.state==='error'){st.innerHTML='<span style="color:#b91c1c">'+t('ota_failed')+': '+esc(d.error)+'</span>'}
  else{st.innerHTML='<span style="color:#64748b">'+line+'</span>'}
  /* Keep the "last checked" line visible alongside a result, except when the
     result already carries the useful information. */
  if(d.state!=='idle'&&d.state!=='checking'&&line&&d.last_check_ago){st.innerHTML+=' <span style="color:#94a3b8">('+line+')</span>'}
  if(busy){watchOta()}
}
/* Poll while something is in flight. Failures are ignored on purpose: writing
   flash disables the cache, so the web server can hitch mid-download and a
   dropped poll means nothing. */
var otaWatch=null;
function watchOta(){
  if(otaWatch){return}
  otaWatch=setInterval(function(){
    fetch('/api/update',{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){
      renderOtaState(d);
      if(d.state!=='checking'&&d.state!=='downloading'&&d.state!=='installing'){
        clearInterval(otaWatch);otaWatch=null;
        /* A reboot follows a successful install; wait it out and say so. */
        if(d.state==='idle'&&d.running){waitForReboot()}
      }
    }).catch(function(){});
  },2000);
}
function saveOtaCfg(){
  var m=document.getElementById('ota-msg');
  var h=document.getElementById('ota-hours').value;
  var a=document.getElementById('ota-auto').checked?'1':'0';
  var u=document.getElementById('ota-url').value.trim();
  fetch('/setotacfg',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:'hours='+encodeURIComponent(h)+'&auto='+a+'&url='+encodeURIComponent(u)})
  .then(function(r){return r.text().then(function(x){
    m.innerHTML=r.ok?('<span style="color:#15803d">'+t('saved')+'</span>')
                    :('<span style="color:#b91c1c">'+t('rejected')+': '+x+'</span>');
    loadUpdateInfo();
  })}).catch(function(){m.innerHTML=t('failed')});
}
function otaCheckNow(){
  var m=document.getElementById('ota-msg');
  m.innerHTML='';
  fetch('/ota/check',{method:'POST'}).then(function(){watchOta()}).catch(function(){});
}
function otaInstallNow(){
  if(!confirm(t('ota_install_confirm'))){return}
  fetch('/ota/install',{method:'POST'}).then(function(){watchOta()}).catch(function(){});
}
function loadFwInfo(){
  /* Kept as the name the settings chain calls; the data now comes from
     /api/update so a page load makes one request, not two. */
  return loadUpdateInfo();
}
/* Waits out the restart, then reports. The delay before the first poll matters:
   the response to the upload arrives while the OLD firmware is still running and
   answering normally, so polling straight away would succeed against the old
   build and reload the page too early. */
function waitForReboot(){
  var m=document.getElementById('fw-msg');
  var tries=0;
  function poll(){
    tries++;
    fetch('/api/session',{cache:'no-store'}).then(function(r){
      if(r.ok){ m.innerHTML='<span style="color:#15803d">'+t('fw_relogin')+'</span>';
                setTimeout(function(){location.reload()},1500); return }
      retry();
    }).catch(retry);
  }
  function retry(){
    if(tries>20){ m.innerHTML='<span style="color:#b45309">'+t('fw_noback')+'</span>'; return }
    setTimeout(poll,2000);
  }
  m.innerHTML=t('fw_wait');
  setTimeout(poll,8000);
}
function otaUpload(){
  var inp=document.getElementById('fw-file');
  var m=document.getElementById('fw-msg');
  var bar=document.getElementById('fw-bar');
  var btn=document.getElementById('fw-btn');
  if(!inp||!inp.files||!inp.files.length){ m.innerHTML='<span style="color:#b45309">'+t('fw_nofile')+'</span>'; return }
  var f=inp.files[0];
  if(!confirm(t('fw_confirm')+' '+f.name+' ('+Math.round(f.size/1024)+' KB)')){return}
  /* XMLHttpRequest rather than fetch: fetch cannot report upload progress. The
     File object is sent as the raw body, so the device needs no form parsing. */
  var xhr=new XMLHttpRequest();
  xhr.open('POST','/ota');
  xhr.setRequestHeader('Content-Type','application/octet-stream');
  btn.disabled=true;
  btn.innerText=t('fw_uploading');
  bar.style.display='block';
  bar.value=0;
  xhr.upload.onprogress=function(e){
    if(e.lengthComputable){
      var pct=Math.round(e.loaded*100/e.total);
      bar.value=pct;
      m.innerHTML=t('fw_uploading')+' '+pct+'%';
    }
  };
  xhr.onload=function(){
    if(xhr.status>=200&&xhr.status<300){
      bar.value=100;
      m.innerHTML='<span style="color:#15803d">'+t('fw_ok')+'</span>';
      waitForReboot();
    }else{
      btn.disabled=false;
      btn.innerText=t('fw_upload_btn');
      bar.style.display='none';
      /* textContent, not innerHTML: this is whatever the device sent back. */
      m.innerHTML='<span style="color:#b91c1c">'+t('fw_failed')+': </span>';
      m.appendChild(document.createTextNode(xhr.responseText||''));
    }
  };
  /* A network error here usually means the device restarted before it could
     reply, which is a success - so follow the same wait path. */
  xhr.onerror=function(){ waitForReboot() };
  xhr.send(f);
}
function changePass(){
  var pass=document.getElementById('new-pass').value;
  if(pass.length<8){alert(t('pass_short'));return}
  var btn=event.target;btn.innerText='...';
  fetch('/setpass',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'pass='+encodeURIComponent(pass)})
  .then(function(r){document.getElementById('settings-msg').innerHTML=r.ok?t('pass_changed'):t('pass_failed')})
  .finally(function(){btn.innerText=t('change_pass_btn')});
}
function resetAP(){
  if(!confirm(t('reset_confirm'))){return}
  fetch('/resetpass',{method:'POST'}).then(function(r){
    if(r.ok){alert(t('reset_done'));location.reload()}else{alert(t('reset_failed'))}
  });
}

/* ---- session / roles ---- */
/* Default to guest, not admin: this is read before loadSession() resolves, and
   it is also the correct fallback if that request fails. Defaulting to admin
   let the boot-time applyLang() reach refreshActiveTab() with the guard open,
   so a visitor's browser fired /status and /scan and logged 401s. */
var SESSION={auth_enabled:false,role:'guest',user:'',client_ip:''};
/* Bumped whenever the role changes. A load chain that is still in flight when
   the user logs out (or back in) would otherwise keep running, 401 on the
   remaining requests and could write stale data into the DOM after a re-login. */
var loadGen=0;
function showLogin(){
  document.getElementById('lg-err').textContent='';
  document.getElementById('lg-pass').value='';
  document.getElementById('lg-user').value=SESSION.user||'admin';
  document.getElementById('modal').style.display='flex';
  document.getElementById('lg-pass').focus();
}
function hideLogin(){document.getElementById('modal').style.display='none'}
function authButton(){
  if(SESSION.role==='admin' && SESSION.auth_enabled){ doLogout() } else { showLogin() }
}
function loadSession(){
  var gen=++loadGen;
  return fetch('/api/session').then(function(r){return r.json()}).then(function(d){
    if(gen!==loadGen){return}   /* a newer transition already won */
    SESSION=d;
    var btn=document.getElementById('auth-btn');
    if(SESSION.auth_enabled){
      btn.textContent=(SESSION.role==='admin')?t('logout_btn'):t('login_btn');
    }else{
      btn.textContent=t('login_btn');
      btn.style.display='none';   /* nothing to log into */
    }
    var admin=(SESSION.role==='admin');
    document.getElementById('admin-view').style.display=admin?'block':'none';
    document.getElementById('guest-view').style.display=admin?'none':'block';
    if(admin){
      /* Show the AP password and the rest of the admin state. */
      fetch('/api/appass').then(function(r){return r.json()}).then(function(x){
        document.getElementById('current-pass').value=x.password||t('no_pass_set');
      }).catch(function(){});
      loadSettings(gen);
      init();
    }else{
      var g=document.getElementById('guest-ident');
      g.innerHTML=SESSION.client_ip ? (t('guest_you')+': <b>'+SESSION.client_ip+'</b>') : '';
      loadGuestView();
    }
    applyLang();   /* re-label the buttons now that the role is known */
  }).catch(function(){
    /* Session lookup failed: show the guest view rather than the admin one. */
    document.getElementById('admin-view').style.display='none';
    document.getElementById('guest-view').style.display='block';
  });
}
function doLogin(){
  var u=document.getElementById('lg-user').value.trim();
  var p=document.getElementById('lg-pass').value;
  var e=document.getElementById('lg-err');
  fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'user='+encodeURIComponent(u)+'&pass='+encodeURIComponent(p)})
  .then(function(r){
    if(r.ok){ hideLogin(); return loadSession() }
    e.textContent=t('login_failed');
  }).catch(function(){ e.textContent=t('login_failed') });
}
function doLogout(){
  fetch('/logout',{method:'POST'}).then(function(){ loadSession() });
}
/* A 401 from anywhere means the session went away; drop to the guest view. */
function guard(resp){
  if(resp && resp.status===401){ loadSession(); return false }
  return true;
}

applyLang();initPresets();loadSession();
</script></body></html>"""


def to_c_literal(text):
    out = []
    # Escape backslashes and double quotes, then emit one literal per line.
    for line in text.split("\n"):
        esc = line.replace("\\", "\\\\").replace('"', '\\"')
        out.append('"%s"' % esc)
    return "\n".join(out)


def _dict_keys(html, lang):
    """Collect the keys of one language block by scanning lines between the
    `en:{` / `zh:{` marker and its closing brace. Regex over the whole block was
    brittle about the trailing comma; line scanning is not."""
    lines = html.split("\n")
    start = None
    for i, ln in enumerate(lines):
        if ln.strip() == lang + ":{":
            start = i + 1
            break
    if start is None:
        return None
    keys = set()
    for ln in lines[start:]:
        t = ln.strip()
        if t in ("},", "}"):
            break
        m = re.findall(r"([A-Za-z0-9_]+):'", ln)
        keys.update(m)
    return keys


def _strip_strings(js):
    """Blank out string literals so a scanner cannot mistake content for syntax.
    Handles ' " and escapes; enough for this document, and it fails safe."""
    out = []
    i = 0
    quote = None
    while i < len(js):
        c = js[i]
        if quote:
            if c == "\\" and i + 1 < len(js):
                i += 2
                continue
            if c == quote:
                quote = None
            out.append(" ")
        else:
            if c in "'\"":
                quote = c
                out.append(" ")
            else:
                out.append(c)
        i += 1
    return "".join(out)


def check_line_comments(html):
    """The page is embedded as one C string literal per line, so the newlines are
    gone once compiled. A // comment would therefore consume the rest of the
    script, truncating it. Strings are stripped first so that a URL inside a
    literal is not mistaken for a comment."""
    js = re.search(r"<script>(.*?)</script>", html, re.S)
    body = js.group(1) if js else html
    stripped = _strip_strings(body)
    # Remove block comments first: explanatory prose inside /* */ may itself
    # mention the token being searched for.
    stripped = re.sub(r"/\*.*?\*/", " ", stripped, flags=re.S)
    hits = re.findall(r"//[^\n]*", stripped)
    if hits:
        print("  !! line comment(s) would eat the rest of the script: %s" % hits[:3])
        return False
    return True


def check_apostrophes(html):
    """An apostrophe inside a single-quoted JS string terminates it, which makes
    the whole script unparseable and leaves a blank panel. node --check catches
    it, but only if someone runs it, so it is checked here too.

    Block comments are stripped first: prose inside /* */ may contain an
    apostrophe quite legitimately, and flagging that would be a false alarm."""
    js = re.search(r"<script>(.*?)</script>", html, re.S)
    body = js.group(1) if js else html
    body = re.sub(r"/\*.*?\*/", " ", body, flags=re.S)
    hits = sorted(set(re.findall(r"[A-Za-z]'[A-Za-z]", body)))
    if hits:
        print("  !! apostrophe inside a JS string will break the script: %s" % hits)
        return False
    return True


def check_keys(html):
    """Every referenced key must exist in both dictionaries - a missing one shows
    up as the raw key in the UI, which slips through unless checked mechanically."""
    refs = set(re.findall(r"data-i18n(?:-ph|-opt)?='([a-z0-9_]+)'", html))
    refs |= set(re.findall(r"\bt\('([a-z0-9_]+)'\)", html))
    print("  referenced keys: %d" % len(refs))
    ok = True
    for lang in ("en", "zh"):
        keys = _dict_keys(html, lang)
        if keys is None:
            print("  !! could not find the %s dictionary" % lang)
            return False
        missing = sorted(refs - keys)
        print("  %s: %d keys defined" % (lang, len(keys)))
        if missing:
            print("  !! %s MISSING: %s" % (lang, missing))
            ok = False
    # Keys can also be reached indirectly, e.g. as values in the DOH_STATE map,
    # so count any quoted occurrence rather than only t('...') calls.
    for k in list(refs):
        pass
    indirect = set(re.findall(r"'([a-z0-9_]+)'", html))
    unused = sorted(_dict_keys(html, "en") - refs - indirect)
    if unused:
        print("  en keys not referenced: %s" % unused)
    return ok


def main():
    path = sys.argv[1]
    if not check_line_comments(HTML):
        sys.exit("refusing to generate: a // comment would truncate the script")
    if not check_apostrophes(HTML):
        sys.exit("refusing to generate: apostrophes would break the JS")
    if not check_keys(HTML):
        sys.exit("refusing to generate: translation keys do not line up")
    src = open(path, encoding="utf-8").read()
    start = src.index('static const char *html_page =')
    end = src.index('static esp_err_t root_get_handler')
    block = 'static const char *html_page =\n' + to_c_literal(HTML) + ';\n\n'
    src = src[:start] + block + src[end:]
    # UTF-8 for the Chinese strings, and an explicit charset on the response.
    src = src.replace('httpd_resp_set_type(req, "text/html");',
                      'httpd_resp_set_type(req, "text/html; charset=utf-8");', 1)
    open(path, "w", encoding="utf-8").write(src)

    # The C literal drops the newlines, so validate the script the way it will
    # actually be served. Written next to the source for an external check.
    js = re.search(r"<script>(.*?)</script>", HTML, re.S)
    if js:
        import os
        flat = js.group(1).replace("\n", "")
        with open(os.path.join(os.path.dirname(path), "page_as_served.js"), "w",
                  encoding="utf-8") as fh:
            fh.write(flat)
        print("  wrote page_as_served.js (%d chars, newlines stripped)" % len(flat))

    print("  spliced: %d bytes of HTML" % len(HTML))


if __name__ == "__main__":
    main()
