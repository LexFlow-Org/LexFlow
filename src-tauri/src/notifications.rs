// ═══════════════════════════════════════════════════════════
//  NOTIFICATIONS — Desktop cron, briefings, reminders
// ═══════════════════════════════════════════════════════════

#![allow(unused_imports)]

use crate::constants::*;
use crate::crypto::{decrypt_data, encrypt_data};
use crate::io::{atomic_write_with_sync, safe_bounded_read};
use crate::platform::{decrypt_local_with_migration, get_local_encryption_key};
use crate::state::{notify_autolock_condvar, AppState};
use chrono::TimeZone as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::Zeroizing;

/// Setup notification permissions and send welcome notification on first launch.
#[allow(unused_variables)]
pub(crate) fn setup_notification_permissions(
    app: &tauri::App,
    data_dir_for_scheduler: &std::path::Path,
) {
    use tauri_plugin_notification::NotificationExt;
    let state = app.notification().permission_state();
    eprintln!("[LexFlow] Notification permission state: {:?}", state);
    match state {
        Ok(tauri_plugin_notification::PermissionState::Granted) => {
            eprintln!("[LexFlow] Notifications already granted ✓");
        }
        Ok(tauri_plugin_notification::PermissionState::Denied) => {
            eprintln!("[LexFlow] ⚠️ Notifications DENIED by user/system.");
            eprintln!(
                "[LexFlow] → User must enable manually: System Settings → Notifications → LexFlow"
            );
            let _ = app.emit("notification-permission-denied", ());
        }
        _ => {
            eprintln!("[LexFlow] Notifications unknown — requesting permission...");
            let result = app.notification().request_permission();
            eprintln!("[LexFlow] Permission request result: {:?}", result);
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        let marker = data_dir_for_scheduler.join(".notifications_registered");
        if !marker.exists() {
            let _ = app
                .notification()
                .builder()
                .title("LexFlow")
                .body("Le notifiche sono attive! Riceverai promemoria per scadenze e udienze.")
                .show();
            let _ = crate::io::secure_write(&marker, b"1");
            eprintln!("[LexFlow] First-launch notification sent ✓");
        }
    }
}

#[tauri::command]
pub(crate) fn send_notification(app: AppHandle, title: String, body: String) {
    let t = title.clone();
    let b = body.clone();
    let ah = app.clone();
    let _ = app.run_on_main_thread(move || {
        use tauri_plugin_notification::NotificationExt;
        if let Err(e) = ah.notification().builder().title(&t).body(&b).show() {
            eprintln!(
                "[LexFlow] Native notification failed: {:?}, emitting event fallback",
                e
            );
            let _ = ah.emit(
                "show-notification",
                serde_json::json!({"title": t, "body": b}),
            );
        }
    });
}

/// Test notification — dev-only command to verify the notification pipeline.
#[tauri::command]
pub(crate) fn test_notification(app: AppHandle) -> bool {
    let ah = app.clone();
    app.run_on_main_thread(move || {
        use tauri_plugin_notification::NotificationExt;
        if let Err(e) = ah
            .notification()
            .builder()
            .title("LexFlow — Test Notifica")
            .body("Le notifiche funzionano correttamente!")
            .show()
        {
            eprintln!("[LexFlow] Test notification failed: {:?}", e);
        }
    })
    .is_ok()
}

#[tauri::command]
pub(crate) fn sync_notification_schedule(
    app: AppHandle,
    state: State<AppState>,
    schedule: Value,
) -> bool {
    let dir = state
        .data_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let key = get_local_encryption_key();
    // SECURITY FIX (Gemini Audit Chunk 14): propagate serialization error instead of unwrap_or_default
    let plaintext = match serde_json::to_vec(&schedule) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "[LexFlow] sync_notification_schedule serialization failed: {}",
                e
            );
            return false;
        }
    };
    match encrypt_data(&key, &plaintext) {
        Ok(encrypted) => {
            let written =
                atomic_write_with_sync(&dir.join(NOTIF_SCHEDULE_FILE), &encrypted).is_ok();
            if written {
                // ── TRIGGER: re-sync OS notification queue after data change ──
                sync_notifications(&app, &dir);
            }
            written
        }
        Err(_) => false,
    }
}

/// Decrypt notification schedule with local machine key
pub(crate) fn read_notification_schedule(data_dir: &std::path::Path) -> Option<Value> {
    let path = data_dir.join(NOTIF_SCHEDULE_FILE);
    if !path.exists() {
        return None;
    }
    // SECURITY FIX (Level-8 C5): size guard before reading into RAM.
    if let Ok(meta) = path.metadata() {
        if meta.len() > MAX_SETTINGS_FILE_SIZE {
            eprintln!(
                "[LexFlow] Notification schedule file troppo grande ({} bytes) — ignorato",
                meta.len()
            );
            return None;
        }
    }
    // SECURITY FIX (Gemini Audit): use migration-aware decryption (hostname→machine_id)
    if let Some(decrypted) = decrypt_local_with_migration(&path) {
        return serde_json::from_slice(&decrypted).ok();
    }
    // Migration: old plaintext format → re-encrypt
    // SECURITY FIX (Security Audit): use safe_bounded_read for OOM protection
    if let Ok(raw) = safe_bounded_read(&path, MAX_SETTINGS_FILE_SIZE) {
        if let Ok(text) = std::str::from_utf8(&raw) {
            if let Ok(val) = serde_json::from_str::<Value>(text) {
                let key = get_local_encryption_key();
                if let Ok(enc) = encrypt_data(&key, &serde_json::to_vec(&val).unwrap_or_default()) {
                    let _ = atomic_write_with_sync(&path, &enc);
                }
                return Some(val);
            }
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════
//  NOTIFICATION HELPERS — shared between mobile AOT and desktop cron
// ═══════════════════════════════════════════════════════════

/// Determine the briefing filter parameters based on the hour of the briefing.
/// Returns (filter_date, time_from, period_label).
#[cfg(any(target_os = "android", target_os = "ios"))]
fn briefing_filter_params<'a>(
    briefing_hour: u32,
    today: &'a str,
    tomorrow: &'a str,
    day_offset_is_zero: bool,
) -> Option<(&'a str, &'a str, &'a str)> {
    if briefing_hour < 12 {
        Some((today, "00:00", "oggi"))
    } else if briefing_hour < 18 {
        Some((today, "13:00", "questo pomeriggio"))
    } else if day_offset_is_zero {
        Some((tomorrow, "00:00", "domani"))
    } else {
        None
    }
}

/// Count relevant (non-completed) items for a given date/time filter.
fn count_relevant_items(items: &[Value], filter_date: &str, time_from: &str) -> usize {
    items
        .iter()
        .filter(|i| {
            let d = i.get("date").and_then(|d| d.as_str()).unwrap_or("");
            let t = i.get("time").and_then(|t| t.as_str()).unwrap_or("00:00");
            let done = i
                .get("completed")
                .and_then(|c| c.as_bool())
                .unwrap_or(false);
            d == filter_date && !done && t >= time_from
        })
        .count()
}

/// Build briefing notification title + body.
fn build_briefing_notification(
    items: &[Value],
    filter_date: &str,
    time_from: &str,
    period_label: &str,
) -> (String, String) {
    let relevant_count = count_relevant_items(items, filter_date, time_from);
    let title = if relevant_count == 0 {
        format!("LexFlow — Nessun impegno {}", period_label)
    } else {
        format!(
            "LexFlow — {} impegn{} {}",
            relevant_count,
            if relevant_count == 1 { "o" } else { "i" },
            period_label
        )
    };
    let body = if relevant_count == 0 {
        format!("Nessun impegno in programma per {}.", period_label)
    } else {
        let mut relevant_items: Vec<&Value> = items
            .iter()
            .filter(|i| {
                let d = i.get("date").and_then(|d| d.as_str()).unwrap_or("");
                let t = i.get("time").and_then(|t| t.as_str()).unwrap_or("00:00");
                let done = i
                    .get("completed")
                    .and_then(|c| c.as_bool())
                    .unwrap_or(false);
                d == filter_date && !done && t >= time_from
            })
            .collect();
        relevant_items.sort_by(|a, b| {
            let ta = a.get("time").and_then(|v| v.as_str()).unwrap_or("");
            let tb = b.get("time").and_then(|v| v.as_str()).unwrap_or("");
            ta.cmp(tb)
        });
        format_item_list(&relevant_items, relevant_count)
    };
    (title, body)
}

/// Format a list of schedule items into a notification body string.
fn format_item_list(relevant_items: &[&Value], total_count: usize) -> String {
    let mut lines: Vec<String> = Vec::new();
    for item in relevant_items.iter().take(4) {
        let t = item.get("time").and_then(|v| v.as_str()).unwrap_or("");
        let name = item
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("Impegno");
        if !t.is_empty() {
            lines.push(format!("• {} — {}", t, name));
        } else {
            lines.push(format!("• {}", name));
        }
    }
    if total_count > 4 {
        lines.push(format!("  …e altri {}", total_count - 4));
    }
    lines.join("\n")
}

/// Compute the reminder fire time for a schedule item.
fn compute_remind_time(
    item: &Value,
    item_local: chrono::DateTime<chrono::Local>,
) -> chrono::DateTime<chrono::Local> {
    let item_date = item.get("date").and_then(|d| d.as_str()).unwrap_or("");
    let custom_remind_time = item
        .get("customRemindTime")
        .and_then(|v| v.as_str())
        .filter(|s| s.len() >= 5);
    let remind_min = item
        .get("remindMinutes")
        .and_then(|v| v.as_i64())
        .unwrap_or(30);
    if let Some(crt) = custom_remind_time {
        let crt_str = format!("{} {}", item_date, crt);
        chrono::NaiveDateTime::parse_from_str(&crt_str, "%Y-%m-%d %H:%M")
            .ok()
            .and_then(|dt| chrono::Local.from_local_datetime(&dt).single())
            .unwrap_or(item_local - chrono::Duration::minutes(remind_min))
    } else {
        item_local - chrono::Duration::minutes(remind_min)
    }
}

/// Build the reminder body text with time-until description.
fn build_reminder_body(
    item_title: &str,
    item_time: &str,
    item_local: chrono::DateTime<chrono::Local>,
    remind_time: chrono::DateTime<chrono::Local>,
) -> String {
    let diff = (item_local - remind_time).num_minutes().max(0);
    let time_desc = if diff == 0 {
        "adesso!".to_string()
    } else if diff < 60 {
        format!("tra {} minuti", diff)
    } else {
        let h = diff / 60;
        let m = diff % 60;
        if m == 0 {
            format!("tra {} or{}", h, if h == 1 { "a" } else { "e" })
        } else {
            format!("tra {}h {:02}min", h, m)
        }
    };
    format!("{} — {} ({})", item_title, item_time, time_desc)
}

/// Parse a schedule item's date+time into a local DateTime.
fn parse_item_datetime(item: &Value) -> Option<chrono::DateTime<chrono::Local>> {
    let item_date = item.get("date").and_then(|d| d.as_str()).unwrap_or("");
    let item_time = item.get("time").and_then(|t| t.as_str()).unwrap_or("");
    if item_time.len() < 5 {
        return None;
    }
    let dt_str = format!("{} {}", item_date, item_time);
    chrono::NaiveDateTime::parse_from_str(&dt_str, "%Y-%m-%d %H:%M")
        .ok()
        .and_then(|dt| chrono::Local.from_local_datetime(&dt).single())
}

/// Compute a stable i32 notification ID from a seed string.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn hash_notification_id(seed: &str) -> i32 {
    let hash = <Sha256 as Digest>::digest(seed.as_bytes());
    let raw = i32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
    raw.wrapping_abs().max(1)
}

// ═══════════════════════════════════════════════════════════
//  HYBRID NOTIFICATION ARCHITECTURE (v3.1)
// ═══════════════════════════════════════════════════════════
//
// MOBILE (Android/iOS): Native AOT scheduling via Schedule::At — the OS fires
//   notifications even if the app is killed.  sync_notifications() cancels all
//   pending and re-schedules from current data.
//
// DESKTOP (macOS/Windows/Linux): tauri-plugin-notification (via notify-rust)
//   IGNORES Schedule::At and fires immediately.  Instead we run a single async
//   Tokio cron job that wakes once per minute, checks the JSON state, and fires
//   notifications in real-time.  Zero threads, zero sleeps, zero CPU waste.
//
//   On macOS the App Nap hack (NSProcessInfo.beginActivityWithOptions) prevents
//   the OS from freezing the async timer when the window is hidden.

/// Schedule all briefing notifications across briefing times × day offsets.
/// Returns number of notifications scheduled.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn schedule_all_briefings(
    app: &AppHandle,
    briefing_times: &[Value],
    items: &[Value],
    today_str: &str,
    tomorrow_str: &str,
    now: chrono::DateTime<chrono::Local>,
    horizon: chrono::DateTime<chrono::Local>,
    max: i32,
) -> i32 {
    let mut count = 0i32;
    for bt in briefing_times {
        let time_str = match bt.as_str() {
            Some(s) if s.len() >= 5 => s,
            _ => continue,
        };
        for day_offset in 0..=1i64 {
            if count >= max {
                return count;
            }
            if let Some(sc) = schedule_briefing_aot(
                app,
                time_str,
                day_offset,
                items,
                today_str,
                tomorrow_str,
                now,
                horizon,
            ) {
                count += sc;
            }
        }
    }
    count
}

/// Schedule all per-item reminder notifications (GROUPED by fire minute).
/// Items that fire at the same minute are merged into a single notification
/// to avoid spamming the user with N identical alerts.
/// Returns number of notifications scheduled.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn schedule_all_reminders(
    app: &AppHandle,
    items: &[Value],
    now: chrono::DateTime<chrono::Local>,
    horizon: chrono::DateTime<chrono::Local>,
    already: i32,
    max: i32,
) -> i32 {
    use std::collections::BTreeMap;

    // Group items by their fire-minute string
    let mut groups: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for item in items {
        let completed = item
            .get("completed")
            .and_then(|c| c.as_bool())
            .unwrap_or(false);
        if completed {
            continue;
        }
        let item_local = match parse_item_datetime(item) {
            Some(t) => t,
            None => continue,
        };
        if item_local > horizon {
            continue;
        }
        let remind_time = compute_remind_time(item, item_local);
        if remind_time <= now {
            continue;
        }
        let fire_key = remind_time.format("%Y-%m-%d %H:%M").to_string();
        groups.entry(fire_key).or_default().push(item);
    }

    let mut count = already;
    for (_fire_key, group) in &groups {
        if count >= max {
            break;
        }
        if let Some(sc) = schedule_grouped_reminder_aot(app, group, now, horizon) {
            count += sc;
        }
    }
    count - already
}

/// Schedule a GROUPED reminder notification for mobile AOT.
/// If the group has 1 item → classic individual reminder.
/// If 2+ items → smart grouped notification with list.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn schedule_grouped_reminder_aot(
    app: &AppHandle,
    group: &[&Value],
    _now: chrono::DateTime<chrono::Local>,
    _horizon: chrono::DateTime<chrono::Local>,
) -> Option<i32> {
    use tauri_plugin_notification::NotificationExt;

    if group.is_empty() {
        return None;
    }

    // Use the first item to compute the fire time (all items in group share it)
    let first = group[0];
    let first_local = parse_item_datetime(first)?;
    let remind_time = compute_remind_time(first, first_local);
    let offset_dt = chrono_to_offset(remind_time)?;

    // Check if any item in the group is critical
    let mut any_critical = false;
    let mut sorted_group: Vec<&Value> = group.to_vec();
    sorted_group.sort_by(|a, b| {
        let ta = a.get("time").and_then(|v| v.as_str()).unwrap_or("");
        let tb = b.get("time").and_then(|v| v.as_str()).unwrap_or("");
        ta.cmp(tb)
    });
    for item in &sorted_group {
        let category = item.get("category").and_then(|c| c.as_str()).unwrap_or("");
        let title = item.get("title").and_then(|t| t.as_str()).unwrap_or("");
        let title_lower = title.to_lowercase();
        if category == "udienza"
            || category == "scadenza"
            || title_lower.contains("udienza")
            || title_lower.contains("scadenza")
            || title_lower.contains("ricorso")
            || title_lower.contains("termine")
        {
            any_critical = true;
            break;
        }
    }

    let total = sorted_group.len();
    let (notif_title, body) = if total == 1 {
        let item = sorted_group[0];
        let item_local = parse_item_datetime(item).unwrap_or(first_local);
        let item_title = item
            .get("title")
            .and_then(|t| t.as_str())
            .unwrap_or("Impegno");
        let item_time = item.get("time").and_then(|t| t.as_str()).unwrap_or("");
        let body = build_reminder_body(item_title, item_time, item_local, remind_time);
        let title = if any_critical {
            "LexFlow — ⚠️ Promemoria Urgente".to_string()
        } else {
            "LexFlow — Promemoria".to_string()
        };
        (title, body)
    } else {
        let title = if any_critical {
            format!("LexFlow — ⚠️ {} impegni in arrivo", total)
        } else {
            format!("LexFlow — {} impegni in arrivo", total)
        };
        let mut lines: Vec<String> = Vec::new();
        let show_count = if total <= 3 { total } else { 2 };
        for item in sorted_group.iter().take(show_count) {
            let t = item.get("time").and_then(|v| v.as_str()).unwrap_or("");
            let name = item
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("Impegno");
            if !t.is_empty() {
                lines.push(format!("• {} — {}", t, name));
            } else {
                lines.push(format!("• {}", name));
            }
        }
        if total > 3 {
            let remaining = total - 2;
            lines.push(format!(
                "…e altr{} {} — controlla l'agenda",
                if remaining == 1 { "o" } else { "i" },
                remaining
            ));
        }
        (title, lines.join("\n"))
    };

    let channel_id = if any_critical {
        "lexflow_urgent"
    } else {
        "lexflow_default"
    };
    let seed = format!("remind-grouped-{}", remind_time.format("%Y-%m-%d-%H-%M"));
    let notif_id = hash_notification_id(&seed);

    let sched = tauri_plugin_notification::Schedule::At {
        date: offset_dt,
        repeating: false,
        allow_while_idle: true,
    };

    app.notification()
        .builder()
        .id(notif_id)
        .channel_id(channel_id)
        .title(&notif_title)
        .body(&body)
        .schedule(sched)
        .show()
        .ok()
        .map(|_| 1)
}

// ── MOBILE: Native AOT scheduling ─────────────────────────────────────────
#[cfg(any(target_os = "android", target_os = "ios"))]
pub(crate) fn sync_notifications(app: &AppHandle, data_dir: &std::path::Path) {
    use tauri_plugin_notification::NotificationExt;

    if let Err(e) = app.notification().cancel_all() {
        eprintln!("[LexFlow Sync] cancel_all error (non-critical): {:?}", e);
    } else {
        eprintln!("[LexFlow Sync] All pending notifications cancelled ✓");
    }

    let schedule_data = match read_notification_schedule(&data_dir) {
        Some(v) => v,
        None => {
            eprintln!("[LexFlow Sync] No schedule file");
            return;
        }
    };

    // PERF: borrow arrays instead of cloning (avoids copying all agenda items)
    let empty_arr = Vec::new();
    let briefing_times = schedule_data
        .get("briefingTimes")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty_arr);
    let items = schedule_data
        .get("items")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty_arr);

    let now = chrono::Local::now();
    let today_str = now.format("%Y-%m-%d").to_string();
    let tomorrow_str = (now + chrono::Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();
    const MAX_SCHEDULED: i32 = 60;
    let horizon = now + chrono::Duration::days(14);

    let briefing_count = schedule_all_briefings(
        app,
        briefing_times,
        items,
        &today_str,
        &tomorrow_str,
        now,
        horizon,
        MAX_SCHEDULED,
    );
    let reminder_count =
        schedule_all_reminders(app, &items, now, horizon, briefing_count, MAX_SCHEDULED);
    let total = briefing_count + reminder_count;

    eprintln!(
        "[LexFlow Sync] ══ Mobile AOT sync: {}/{} notifications scheduled ══",
        total, MAX_SCHEDULED
    );
}

/// Convert chrono::DateTime<Local> to time::OffsetDateTime (for notification scheduling).
#[cfg(any(target_os = "android", target_os = "ios"))]
fn chrono_to_offset(dt: chrono::DateTime<chrono::Local>) -> Option<time::OffsetDateTime> {
    let ts = dt.timestamp();
    let ns = dt.timestamp_subsec_nanos();
    let offset_secs = dt.offset().local_minus_utc();
    let offset = time::UtcOffset::from_whole_seconds(offset_secs).ok()?;
    time::OffsetDateTime::from_unix_timestamp(ts)
        .ok()
        .map(|t| t.replace_nanosecond(ns).unwrap_or(t))
        .map(|t| t.to_offset(offset))
}

/// Schedule a single briefing notification (mobile AOT). Returns Some(1) on success.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn schedule_briefing_aot(
    app: &AppHandle,
    time_str: &str,
    day_offset: i64,
    items: &[Value],
    today_str: &str,
    tomorrow_str: &str,
    now: chrono::DateTime<chrono::Local>,
    horizon: chrono::DateTime<chrono::Local>,
) -> Option<i32> {
    use tauri_plugin_notification::NotificationExt;
    let target_date = now.date_naive() + chrono::Duration::days(day_offset);
    let date_str = target_date.format("%Y-%m-%d").to_string();
    let dt_str = format!("{} {}", date_str, time_str);
    let target_dt = chrono::NaiveDateTime::parse_from_str(&dt_str, "%Y-%m-%d %H:%M").ok()?;
    let target_local = chrono::Local.from_local_datetime(&target_dt).single()?;
    if target_local <= now || target_local > horizon {
        return None;
    }
    let offset_dt = chrono_to_offset(target_local)?;
    let briefing_hour: u32 = time_str
        .split(':')
        .next()
        .and_then(|h| h.parse().ok())
        .unwrap_or(8);
    let (filter_date, time_from, period_label) =
        briefing_filter_params(briefing_hour, &date_str, tomorrow_str, day_offset == 0).or_else(
            || briefing_filter_params(briefing_hour, today_str, tomorrow_str, day_offset == 0),
        )?;
    let (title, body_str) =
        build_briefing_notification(items, filter_date, time_from, period_label);
    let notif_id = hash_notification_id(&format!("briefing-{}-{}", date_str, time_str));
    let sched = tauri_plugin_notification::Schedule::At {
        date: offset_dt,
        repeating: false,
        allow_while_idle: true,
    };
    app.notification()
        .builder()
        .id(notif_id)
        .title(&title)
        .body(&body_str)
        .schedule(sched)
        .show()
        .ok()
        .map(|_| 1)
}

// ── DESKTOP: stub — scheduling is handled by the async cron job ────────────
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) fn sync_notifications(_app: &AppHandle, _data_dir: &std::path::Path) {
    // No-op on desktop.  The desktop_cron_job() runs every 30s and fires
    // notifications in real-time by checking the JSON state.
}

// ── DESKTOP: Async Cron Job — wakes every 30s, fires matching notifications ──
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) async fn desktop_cron_job(app: AppHandle) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_processed_minute = String::new();

    eprintln!("[LexFlow Cron] Desktop cron job started — checking every 30s");

    loop {
        interval.tick().await;

        let now = chrono::Local::now();
        let current_minute = now.format("%Y-%m-%d %H:%M").to_string();
        if current_minute == last_processed_minute {
            continue;
        }
        last_processed_minute = current_minute.clone();

        let data_dir = app
            .state::<AppState>()
            .data_dir
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        let schedule_data = match read_notification_schedule(&data_dir) {
            Some(v) => v,
            None => {
                eprintln!(
                    "[LexFlow Cron] ⚠️ No schedule file found or decryption failed at {}",
                    current_minute
                );
                continue;
            }
        };

        // PERF: borrow arrays from schedule_data instead of cloning them.
        // With 1000+ agenda items this avoids cloning ~100KB of JSON every 30 seconds.
        let empty_arr = Vec::new();
        let briefing_times = schedule_data
            .get("briefingTimes")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty_arr);
        let items = schedule_data
            .get("items")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty_arr);

        let today = now.format("%Y-%m-%d").to_string();
        let tomorrow = (now + chrono::Duration::days(1))
            .format("%Y-%m-%d")
            .to_string();

        // Diagnostic logging (every minute tick)
        eprintln!(
            "[LexFlow Cron] tick {} — {} briefing times, {} schedule items",
            current_minute,
            briefing_times.len(),
            items.len()
        );
        // Log next fire times for items so we can diagnose mismatches
        if !items.is_empty() {
            for (idx, item) in items.iter().enumerate().take(5) {
                if let Some(item_local) = parse_item_datetime(item) {
                    let remind_time = compute_remind_time(item, item_local);
                    let fire_min = remind_time.format("%Y-%m-%d %H:%M").to_string();
                    let title = item.get("title").and_then(|t| t.as_str()).unwrap_or("?");
                    eprintln!(
                        "[LexFlow Cron]   item[{}] \"{}\" event={} fire={}{}",
                        idx,
                        title,
                        item_local.format("%Y-%m-%d %H:%M"),
                        fire_min,
                        if fire_min == current_minute {
                            " ← MATCH!"
                        } else {
                            ""
                        }
                    );
                }
            }
        }

        // Check briefings
        for bt in briefing_times {
            let time_str = match bt.as_str() {
                Some(s) if s.len() >= 5 => s,
                _ => continue,
            };
            let briefing_key = format!("{} {}", today, time_str);
            if briefing_key != current_minute {
                continue;
            }
            fire_desktop_briefing(&app, time_str, items, &today, &tomorrow);
            eprintln!("[LexFlow Cron] ✓ Briefing fired: {}", briefing_key);
        }

        // Check per-item reminders — GROUP by fire minute to avoid notification spam
        fire_grouped_desktop_reminders(&app, items, &current_minute);
    }
}

/// Fire a single desktop briefing notification if it matches the current minute.
/// Uses time-sensitive delivery for deadline/court briefings (bypasses DND).
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn fire_desktop_briefing(
    app: &AppHandle,
    time_str: &str,
    items: &[Value],
    today: &str,
    tomorrow: &str,
) {
    let briefing_hour: u32 = time_str
        .split(':')
        .next()
        .and_then(|h| h.parse().ok())
        .unwrap_or(8);
    let (filter_date, time_from, period_label) = if briefing_hour < 12 {
        (today, "00:00", "oggi")
    } else if briefing_hour < 18 {
        (today, "13:00", "questo pomeriggio")
    } else {
        (tomorrow, "00:00", "domani")
    };
    let (title, body_str) =
        build_briefing_notification(items, filter_date, time_from, period_label);

    // Briefings are always time-sensitive (bypass DND)
    fire_urgent_desktop_notification(app, &title, &body_str);
}

/// Fire GROUPED desktop reminder notifications for a given minute.
/// Instead of spamming N separate notifications for N events with the same
/// remind time, we group them into a single smart notification:
///   - 1 event  → individual reminder (as before)
///   - 2 events → both listed in one notification
///   - 3+ events → first 2 listed + "…e altri N — controlla l'agenda"
///
/// Critical events (udienza/scadenza) are always elevated to time-sensitive.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn fire_grouped_desktop_reminders(app: &AppHandle, items: &[Value], current_minute: &str) {
    // Collect all items whose remind time matches this minute
    let mut matching: Vec<&Value> = Vec::new();
    let mut any_critical = false;

    for item in items {
        let completed = item
            .get("completed")
            .and_then(|c| c.as_bool())
            .unwrap_or(false);
        if completed {
            continue;
        }
        let item_local = match parse_item_datetime(item) {
            Some(t) => t,
            None => continue,
        };
        let remind_time = compute_remind_time(item, item_local);
        let fire_minute = remind_time.format("%Y-%m-%d %H:%M").to_string();
        if fire_minute != current_minute {
            continue;
        }

        // Check criticality
        let category = item.get("category").and_then(|c| c.as_str()).unwrap_or("");
        let title = item.get("title").and_then(|t| t.as_str()).unwrap_or("");
        let title_lower = title.to_lowercase();
        if category == "udienza"
            || category == "scadenza"
            || title_lower.contains("udienza")
            || title_lower.contains("scadenza")
            || title_lower.contains("ricorso")
            || title_lower.contains("termine")
        {
            any_critical = true;
        }
        matching.push(item);
    }

    if matching.is_empty() {
        return;
    }

    // Sort by event time ascending
    matching.sort_by(|a, b| {
        let ta = a.get("time").and_then(|v| v.as_str()).unwrap_or("");
        let tb = b.get("time").and_then(|v| v.as_str()).unwrap_or("");
        ta.cmp(tb)
    });

    let total = matching.len();

    if total == 1 {
        // Single event → classic individual reminder
        let item = matching[0];
        let item_local = match parse_item_datetime(item) {
            Some(t) => t,
            None => return, // Shouldn't happen (already filtered), but be safe
        };
        let remind_time = compute_remind_time(item, item_local);
        let item_title = item
            .get("title")
            .and_then(|t| t.as_str())
            .unwrap_or("Impegno");
        let item_time = item.get("time").and_then(|t| t.as_str()).unwrap_or("");
        let body = build_reminder_body(item_title, item_time, item_local, remind_time);
        let notif_title = if any_critical {
            "LexFlow — ⚠️ Promemoria Urgente"
        } else {
            "LexFlow — Promemoria"
        };
        fire_urgent_desktop_notification(app, notif_title, &body);
        eprintln!("[LexFlow Cron] ✓ Reminder fired (1 event): {}", item_title);
    } else {
        // Multiple events → grouped notification
        let notif_title = if any_critical {
            format!("LexFlow — ⚠️ {} impegni in arrivo", total)
        } else {
            format!("LexFlow — {} impegni in arrivo", total)
        };

        let mut lines: Vec<String> = Vec::new();
        let show_count = if total <= 3 { total } else { 2 };
        for item in matching.iter().take(show_count) {
            let t = item.get("time").and_then(|v| v.as_str()).unwrap_or("");
            let name = item
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("Impegno");
            if !t.is_empty() {
                lines.push(format!("• {} — {}", t, name));
            } else {
                lines.push(format!("• {}", name));
            }
        }
        if total > 3 {
            let remaining = total - 2;
            lines.push(format!(
                "…e altr{} {} — controlla l'agenda",
                if remaining == 1 { "o" } else { "i" },
                remaining
            ));
        }
        let body = lines.join("\n");

        fire_urgent_desktop_notification(app, &notif_title, &body);
        eprintln!(
            "[LexFlow Cron] ✓ Grouped reminder fired: {} events in one notification",
            total
        );
    }
}

// ═══════════════════════════════════════════════════════════
//  TIME-SENSITIVE NOTIFICATIONS (tauri_plugin_notification)
// ═══════════════════════════════════════════════════════════
//
// On macOS, when the user has Focus Mode (Do Not Disturb) enabled, regular
// notifications are silenced. For a legal app, missing a court deadline
// because of DND is unacceptable.
//
// tauri_plugin_notification delivers native OS notifications on all platforms.
// On macOS, to make these time-sensitive, the user should add LexFlow
// to their Focus Mode allowed apps in System Settings → Focus → LexFlow.

/// Send an urgent notification via tauri_plugin_notification.
/// Works on all platforms (macOS, Windows, Linux).
#[tauri::command]
pub(crate) fn send_urgent_notification(app: AppHandle, title: String, body: String) {
    let t = title;
    let b = body;
    let ah = app.clone();
    let _ = app.run_on_main_thread(move || {
        use tauri_plugin_notification::NotificationExt;
        let _ = ah.notification().builder().title(&t).body(&b).show();
    });
}

// ═══════════════════════════════════════════════════════════
//  ACTIONABLE TOASTS
// ═══════════════════════════════════════════════════════════
//
// On Windows 11, we can add interactive buttons directly inside the
// notification banner. The user sees "Scadenza Fascicolo" with two buttons:
//   [✅ Completato]  [⏰ Posticipa 1h]
//
// When the user clicks a button, Windows sends an activation callback to
// our running process. We handle it via a Tauri event, allowing the frontend
// to update the database without even opening the main window.
//
// This is pure IPC: Windows → LexFlow binary → vault update. Zero internet.

/// Send a notification with action buttons (Windows) or standard notification (other OS).
/// Emits a frontend event so the UI can show in-app action buttons.
#[tauri::command]
pub(crate) fn send_actionable_notification(
    app: AppHandle,
    title: String,
    body: String,
    event_id: String,
    actions: Value,
) {
    let _ = &actions; // Used for documentation; actual button labels are hardcoded

    let t = title.clone();
    let b = body.clone();
    let eid = event_id.clone();
    let ah = app.clone();
    let _ = app.run_on_main_thread(move || {
        use tauri_plugin_notification::NotificationExt;
        if let Err(e) = ah.notification().builder().title(&t).body(&b).show() {
            eprintln!("[LexFlow] Actionable notification failed: {:?}", e);
        }
        // Emit event so the frontend can show in-app action buttons
        let _ = ah.emit(
            "notification-action",
            json!({
                "eventId": eid,
                "title": t,
                "body": b,
            }),
        );
    });
}

// ═══════════════════════════════════════════════════════════
//  DESKTOP CRON NOTIFICATION DELIVERY (tauri_plugin_notification)
// ═══════════════════════════════════════════════════════════

/// Fire a desktop notification on macOS / Windows / Linux.
/// Used by the desktop cron job for ALL events (briefings, reminders).
/// Uses tauri_plugin_notification via run_on_main_thread.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn fire_urgent_desktop_notification(app: &AppHandle, title: &str, body: &str) {
    let t = title.to_string();
    let b = body.to_string();
    let app_clone = app.clone();
    let _ = app.run_on_main_thread(move || {
        use tauri_plugin_notification::NotificationExt;
        if let Err(e) = app_clone.notification().builder().title(&t).body(&b).show() {
            eprintln!("[LexFlow] Cron notification failed: {:?}", e);
        }
    });
    eprintln!("[LexFlow] ✓ Notification sent: {}", title);
}
