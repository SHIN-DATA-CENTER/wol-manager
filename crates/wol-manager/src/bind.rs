//! Wires every global callback of the UI (and the tray) to the app (contract §2–§8).
//!
//! Handlers capture nothing: they look the app up in the thread-local on each call, so no
//! reference cycle between the component and the app exists.

use slint::{CloseRequestResponse, ComponentHandle};

use crate::app::{App, with};
use crate::{AboutInfo, AppState, AppTray, EditorState, FieldIssue, SettingsState, Validator};

/// Connects the window's globals and the close button.
pub fn wire(app: &App) {
    let ui = &app.ui;

    let s = ui.global::<AppState>();
    s.on_wake(|id| {
        with(|a| a.wake(&id, false));
    });
    s.on_wake_all_visible(|| {
        with(|a| a.wake_all_visible());
    });
    s.on_refresh(|| {
        with(|a| a.refresh());
    });
    s.on_add_host(|| {
        with(|a| a.add_host());
    });
    s.on_edit_host(|id| {
        with(|a| a.edit_host(&id));
    });
    s.on_duplicate_host(|id| {
        with(|a| a.duplicate_host(&id));
    });
    s.on_delete_host(|id| {
        with(|a| a.delete_host(&id));
    });
    s.on_copy_mac(|id| {
        with(|a| a.copy_mac(&id));
    });
    s.on_copy_address(|id| {
        with(|a| a.copy_address(&id));
    });
    s.on_search_changed(|text| {
        with(|a| a.search_changed(&text));
    });
    s.on_group_filter_changed(|g| {
        with(|a| a.group_filter_changed(&g));
    });
    s.on_open_settings(|| {
        with(|a| a.open_settings());
    });
    s.on_open_about(|| {
        with(|a| a.open_about());
    });
    s.on_open_config_folder(|| {
        with(|a| a.open_config_folder());
    });
    s.on_open_url(|url| {
        with(|a| a.open_url(&url));
    });
    s.on_close_window(|| {
        with(|a| a.close_window());
    });
    s.on_quit(|| {
        with(|a| a.request_quit());
    });
    s.on_window_minimized(|| {
        with(|a| a.window_minimized());
    });
    s.on_overlay_closed(|kind| {
        with(|a| a.overlay_closed(kind));
    });
    s.on_confirm_accepted(|req, alternate| {
        with(|a| a.confirm_accepted(req, alternate));
    });
    s.on_confirm_cancelled(|req| {
        with(|a| a.confirm_cancelled(req));
    });
    s.on_dismiss_toast(|id| {
        with(|a| a.dismiss_toast(id));
    });
    s.on_notice_action(|kind| {
        with(|a| a.notice_action(kind));
    });
    s.on_dismiss_notice(|kind| {
        with(|a| a.dismiss_notice(kind));
    });
    // v0.2.0 remote management (contract §10.10).
    s.on_restart_host(|id| {
        with(|a| a.restart_host(&id));
    });
    s.on_shutdown_host(|id| {
        with(|a| a.shutdown_host(&id));
    });
    s.on_abort_shutdown(|id| {
        with(|a| a.abort_shutdown(&id));
    });
    s.on_fetch_boot_time(|id| {
        with(|a| a.fetch_boot_time(&id));
    });
    s.on_setup_remote(|id| {
        with(|a| a.setup_remote(&id));
    });
    s.on_power_accepted(|req| {
        with(|a| a.power_accepted(req));
    });
    s.on_power_cancelled(|req| {
        with(|a| a.power_cancelled(req));
    });
    s.on_hostkey_trusted(|p| {
        with(|a| a.hostkey_trusted(p));
    });
    s.on_hostkey_cancelled(|p| {
        with(|a| a.hostkey_cancelled(p));
    });
    s.on_hostkey_forget(|p| {
        with(|a| a.hostkey_forget(p));
    });

    let e = ui.global::<EditorState>();
    e.on_save(|| {
        with(|a| a.save_editor());
    });
    e.on_lookup_mac(|address| {
        with(|a| a.lookup_mac(&address));
    });
    e.on_test_connection(|| {
        with(|a| a.test_connection());
    });
    e.on_mac_picked(|c| {
        with(|a| a.mac_picked(c));
    });

    // Pure callbacks: cheap, no side effects. The config is only borrowed immutably and a
    // failed borrow simply reports no issue.
    let v = ui.global::<Validator>();
    v.on_check_name(|name, host_id| {
        with(|a| match a.cfg.try_borrow() {
            Ok(cfg) => crate::editor::check_name(&cfg, &name, &host_id),
            Err(_) => FieldIssue::None,
        })
        .unwrap_or(FieldIssue::None)
    });
    v.on_check_mac(|t| crate::editor::check_mac(&t));
    v.on_check_address(|t| crate::editor::check_address(&t));
    v.on_check_port(|t| crate::editor::check_port(&t));
    v.on_port_value(|t| crate::editor::port_value(&t));
    v.on_check_targets(|t| crate::editor::check_targets(&t));
    v.on_check_secureon(|t| crate::editor::check_secureon(&t));
    v.on_check_tcp_ports(|t| crate::editor::check_tcp_ports(&t));
    v.on_is_ipv4(|t| crate::editor::is_ipv4(&t));
    v.on_check_remote_user(|t, kind| crate::editor::check_remote_user(&t, kind));

    let st = ui.global::<SettingsState>();
    st.on_changed(|key| {
        with(|a| a.setting_changed(&key));
    });
    st.on_portable_toggled(|on| {
        with(|a| a.portable_toggled(on));
    });
    st.on_path_toggled(|on| {
        with(|a| a.path_toggled(on));
    });
    st.on_open_log_folder(|| {
        with(|a| a.open_log_folder());
    });

    ui.global::<AboutInfo>().on_open_notices(|| {
        with(|a| a.open_notices());
    });

    ui.window().on_close_requested(|| {
        with(|a| a.on_close_requested()).unwrap_or(CloseRequestResponse::HideWindow)
    });

    if let Some(t) = app.tray.borrow().as_ref() {
        wire_tray(&t.tray);
    }
}

/// Connects the tray icon's callbacks.
pub fn wire_tray(tray: &AppTray) {
    tray.on_show_window(|| {
        with(|a| a.show_window());
    });
    tray.on_wake(|id| {
        with(|a| a.wake(&id, true));
    });
    tray.on_open_settings(|| {
        with(|a| {
            a.show_window();
            a.open_settings();
        });
    });
    tray.on_quit(|| {
        with(|a| a.request_quit());
    });
}
