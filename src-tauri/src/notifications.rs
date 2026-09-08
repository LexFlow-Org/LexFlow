// ═══════════════════════════════════════════════════════════
//  NOTIFICATIONS — Desktop cron, briefings, reminders
// ═══════════════════════════════════════════════════════════

use crate::constants::*;
use crate::crypto::encrypt_data;
use crate::io::{atomic_write_with_sync, safe_bounded_read};
use crate::platform::{decrypt_local_with_migration, get_local_encryption_key};
use crate::state::AppState;
use chrono::TimeZone as _;
use serde_json::Value;
#[cfg(any(target_os = "android", target_os = "ios"))]
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, Manager, State};

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

/// Hard cap on the schedule payload coming from the FE (1 MiB is generous —
/// real schedules with 1000+ items serialize to ~100 KiB).
const MAX_SCHEDULE_PAYLOAD: usize = 1024 * 1024;
const MAX_SCHEDULE_ITEMS: usize = 10_000;
const MAX_REMIND_MINUTES: i64 = 14 * 24 * 60;

fn valid_schedule_time(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 5
            && text.as_bytes()[2] == b':'
            && chrono::NaiveTime::parse_from_str(text, "%H:%M").is_ok()
    })
}

fn valid_notification_schedule(schedule: &Value) -> bool {
    let Some(object) = schedule.as_object() else {
        return false;
    };
    let Some(briefings) = object.get("briefingTimes").and_then(Value::as_array) else {
        return false;
    };
    let Some(items) = object.get("items").and_then(Value::as_array) else {
        return false;
    };
    if briefings.len() > 24
        || !briefings.iter().all(valid_schedule_time)
        || items.len() > MAX_SCHEDULE_ITEMS
    {
        return false;
    }
    items.iter().all(|item| {
        let Some(item) = item.as_object() else {
            return false;
        };
        let valid_date = item
            .get("date")
            .and_then(Value::as_str)
            .is_some_and(|text| {
                text.len() == 10 && chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d").is_ok()
            });
        valid_date
            && item.get("time").is_some_and(valid_schedule_time)
            && ["id", "title", "category"].iter().all(|field| {
                item.get(*field)
                    .is_none_or(|value| value.as_str().is_some_and(|text| text.len() <= 4096))
            })
            && item.get("completed").is_none_or(Value::is_boolean)
            && item.get("remindMinutes").is_none_or(|value| {
                value.is_null()
                    || value
                        .as_i64()
                        .is_some_and(|minutes| (0..=MAX_REMIND_MINUTES).contains(&minutes))
            })
            && item.get("customRemindTime").is_none_or(|value| {
                value.is_null() || value.as_str() == Some("") || valid_schedule_time(value)
            })
    })
}

fn notifications_enabled_by_settings(settings: &Value) -> bool {
    settings.as_object().is_some_and(|object| {
        object
            .get("notifyEnabled")
            .is_none_or(|enabled| enabled.as_bool() == Some(true))
    })
}

/// Confidential details require explicit opt-in; errors fail closed.
fn notification_preferences(data_dir: &std::path::Path) -> (bool, bool) {
    let path = data_dir.join(SETTINGS_FILE);
    if !path.exists() {
        return (true, true);
    }
    decrypt_local_with_migration(&path)
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .map(|settings| {
            (
                notifications_enabled_by_settings(&settings),
                details_hidden_by_settings(&settings),
            )
        })
        .unwrap_or((false, true))
}

fn hide_notification_details(data_dir: &std::path::Path) -> bool {
    notification_preferences(data_dir).1
}

fn details_hidden_by_settings(settings: &Value) -> bool {
    settings
        .get("hide_notification_details")
        .and_then(Value::as_bool)
        != Some(false)
}

/// Scheduled mobile notifications may fire after the vault locks. Keep their
/// payload generic so the OS queue never stores case/client titles.
fn redact_scheduled_titles(schedule: &mut Value) {
    if let Some(items) = schedule.get_mut("items").and_then(Value::as_array_mut) {
        for item in items {
            if let Some(object) = item.as_object_mut() {
                object.insert("title".into(), Value::String("Impegno riservato".into()));
            }
        }
    }
}

#[tauri::command]
pub(crate) fn sync_notification_schedule(
    app: AppHandle,
    state: State<AppState>,
    schedule: Value,
) -> bool {
    if !valid_notification_schedule(&schedule) {
        return false;
    }
    let session = match state.document_session() {
        Ok(session) => session,
        Err(_) => return false,
    };
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let mut schedule = schedule;
    if hide_notification_details(&dir) {
        redact_scheduled_titles(&mut schedule);
    }
    let key = get_local_encryption_key();
    // SECURITY FIX (Gemini Audit Chunk 14): propagate serialization error instead of unwrap_or_default
    let plaintext = match serde_json::to_vec(&schedule) {
        Ok(v) => zeroize::Zeroizing::new(v),
        Err(e) => {
            eprintln!(
                "[LexFlow] sync_notification_schedule serialization failed: {}",
                e
            );
            return false;
        }
    };
    // VALIDATION: hard cap on schedule payload to prevent OOM / DoS via
    // a malicious or malformed FE call.
    if plaintext.len() > MAX_SCHEDULE_PAYLOAD {
        eprintln!(
            "[LexFlow] sync_notification_schedule rejected: payload {} bytes > {} bytes",
            plaintext.len(),
            MAX_SCHEDULE_PAYLOAD
        );
        return false;
    }
    match encrypt_data(&key, &plaintext) {
        Ok(encrypted) => {
            let written = {
                let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
                if state.validate_document_session(session).is_err()
                    || *state.data_dir.read().unwrap_or_else(|e| e.into_inner()) != dir
                {
                    return false;
                }
                atomic_write_with_sync(&dir.join(NOTIF_SCHEDULE_FILE), &encrypted).is_ok()
            };
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
        if decrypted.len() > MAX_SCHEDULE_PAYLOAD {
            return None;
        }
        return serde_json::from_slice(&decrypted)
            .ok()
            .filter(valid_notification_schedule);
    }
    // Migration: old plaintext format → re-encrypt
    // SECURITY FIX (Security Audit): use safe_bounded_read for OOM protection
    if let Ok(raw) = safe_bounded_read(&path, MAX_SETTINGS_FILE_SIZE) {
        if let Ok(text) = std::str::from_utf8(&raw) {
            if let Ok(val) = serde_json::from_str::<Value>(text) {
                if raw.len() > MAX_SCHEDULE_PAYLOAD || !valid_notification_schedule(&val) {
                    return None;
                }
                let key = get_local_encryption_key();
                // SECURITY FIX (BE-8 audit): do not silently lose data on
                // serialization/encryption/write failure. If the migration
                // write fails, treat the migration as failed and return None
                // so the caller does not believe the file is now encrypted.
                let bytes = match serde_json::to_vec(&val) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!(
                            "[LexFlow] schedule migration serialize failed: {} — keeping plaintext",
                            e
                        );
                        return Some(val);
                    }
                };
                let enc = match encrypt_data(&key, &bytes) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("[LexFlow] schedule migration encrypt failed: {}", e);
                        return Some(val);
                    }
                };
                if let Err(e) = atomic_write_with_sync(&path, &enc) {
                    eprintln!("[LexFlow] schedule migration write failed: {}", e);
                    // Don't claim the on-disk migration succeeded — caller still
                    // gets the parsed value but the file remains plaintext.
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
///
/// SEMANTICS (audit):
///   - filter_date is the date whose items are summarised in the briefing.
///   - dates and labels are relative to the day the briefing actually fires.
#[cfg(any(test, target_os = "android", target_os = "ios"))]
fn briefing_filter_params(
    briefing_hour: u32,
    briefing_date: chrono::NaiveDate,
) -> Option<(String, &'static str, &'static str)> {
    let (date, time_from, period) = if briefing_hour < 12 {
        (briefing_date, "00:00", "oggi")
    } else if briefing_hour < 18 {
        (briefing_date, "13:00", "questo pomeriggio")
    } else {
        (briefing_date.succ_opt()?, "00:00", "domani")
    };
    Some((date.format("%Y-%m-%d").to_string(), time_from, period))
}

/// Collect the (filtered, sorted) relevant items for a given date/time filter.
fn collect_relevant_items<'a>(
    items: &'a [Value],
    filter_date: &str,
    time_from: &str,
) -> Vec<&'a Value> {
    let mut out: Vec<&Value> = items
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
    out.sort_by(|a, b| {
        let ta = a.get("time").and_then(|v| v.as_str()).unwrap_or("");
        let tb = b.get("time").and_then(|v| v.as_str()).unwrap_or("");
        ta.cmp(tb)
    });
    out
}

/// Build briefing notification title + body.
fn build_briefing_notification(
    items: &[Value],
    filter_date: &str,
    time_from: &str,
    period_label: &str,
) -> (String, String) {
    // DRY: collect once, derive both count and body from the same list.
    let relevant_items = collect_relevant_items(items, filter_date, time_from);
    let relevant_count = relevant_items.len();
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
) -> Option<chrono::DateTime<chrono::Local>> {
    let item_date = item.get("date").and_then(|d| d.as_str()).unwrap_or("");
    // BUG FIX (audit): require exact "HH:MM" shape — len == 5 AND ':' at index 2.
    let custom_remind_time = item
        .get("customRemindTime")
        .and_then(|v| v.as_str())
        .filter(|s| s.len() == 5 && s.as_bytes().get(2) == Some(&b':'));
    let remind_min = match item.get("remindMinutes") {
        None | Some(Value::Null) => 30,
        Some(value) => value.as_i64()?,
    };
    if !(0..=MAX_REMIND_MINUTES).contains(&remind_min) {
        return None;
    }
    let fallback = || item_local.checked_sub_signed(chrono::Duration::try_minutes(remind_min)?);
    if let Some(crt) = custom_remind_time {
        let crt_str = format!("{} {}", item_date, crt);
        chrono::NaiveDateTime::parse_from_str(&crt_str, "%Y-%m-%d %H:%M")
            .ok()
            // DST FIX: .single() returns None on ambiguous (fall back) times.
            // Prefer .earliest() and warn via stderr if ambiguous.
            .and_then(|dt| {
                let mapped = chrono::Local.from_local_datetime(&dt);
                if matches!(mapped, chrono::LocalResult::Ambiguous(..)) {
                    eprintln!(
                        "[LexFlow] DST ambiguous customRemindTime '{}' — picking earliest",
                        crt_str
                    );
                }
                mapped.earliest()
            })
            .or_else(fallback)
    } else {
        fallback()
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
        .and_then(|dt| {
            // DST FIX: .single() drops ambiguous local times. Use .earliest()
            // and log when the input is ambiguous so we don't silently miss
            // notifications during a fall-back hour.
            let mapped = chrono::Local.from_local_datetime(&dt);
            if matches!(mapped, chrono::LocalResult::Ambiguous(..)) {
                eprintln!(
                    "[LexFlow] DST ambiguous item datetime '{}' — picking earliest",
                    dt_str
                );
            }
            mapped.earliest()
        })
}

/// Compute a stable i32 notification ID from a seed string.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn hash_notification_id(seed: &str) -> i32 {
    let hash = <Sha256 as Digest>::digest(seed.as_bytes());
    let raw = i32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
    // SECURITY FIX: wrapping_abs on i32::MIN returns i32::MIN (negative).
    // Use bitmask to ensure positive without collision.
    (raw & 0x7FFF_FFFF).max(1)
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
            if let Some(sc) = schedule_briefing_aot(app, time_str, day_offset, items, now, horizon)
            {
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
        let Some(remind_time) = compute_remind_time(item, item_local) else {
            continue;
        };
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
    let remind_time = compute_remind_time(first, first_local)?;
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

    // Serialize replacement of the OS queue with preference-triggered cancellation.
    static QUEUE_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _queue_guard = QUEUE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    if let Err(e) = app.notification().cancel_all() {
        eprintln!("[LexFlow Sync] cancel_all error (non-critical): {:?}", e);
    } else {
        eprintln!("[LexFlow Sync] All pending notifications cancelled ✓");
    }

    if !notification_preferences(data_dir).0 {
        return;
    }

    let mut schedule_data = match read_notification_schedule(&data_dir) {
        Some(v) => v,
        None => {
            eprintln!("[LexFlow Sync] No schedule file");
            return;
        }
    };

    redact_scheduled_titles(&mut schedule_data);

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
    const MAX_SCHEDULED: i32 = 60;
    let horizon = now + chrono::Duration::days(14);

    let briefing_count =
        schedule_all_briefings(app, briefing_times, items, now, horizon, MAX_SCHEDULED);
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
    now: chrono::DateTime<chrono::Local>,
    horizon: chrono::DateTime<chrono::Local>,
) -> Option<i32> {
    use tauri_plugin_notification::NotificationExt;
    let target_date = now.date_naive() + chrono::Duration::days(day_offset);
    let date_str = target_date.format("%Y-%m-%d").to_string();
    let dt_str = format!("{} {}", date_str, time_str);
    let target_dt = chrono::NaiveDateTime::parse_from_str(&dt_str, "%Y-%m-%d %H:%M").ok()?;
    // DST FIX: .single() returns None on ambiguous local times.
    let target_local = {
        let mapped = chrono::Local.from_local_datetime(&target_dt);
        if matches!(mapped, chrono::LocalResult::Ambiguous(..)) {
            eprintln!(
                "[LexFlow] DST ambiguous briefing target '{}' — picking earliest",
                dt_str
            );
        }
        mapped.earliest()?
    };
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
        briefing_filter_params(briefing_hour, target_date)?;
    let (title, body_str) =
        build_briefing_notification(items, &filter_date, time_from, period_label);
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

        // CONCURRENCY/SEC: integration with vault lock state — if locked, only
        // fire generic-body notifications (no PII like client/case names) so
        // the OS lockscreen / notification center never reveals confidential
        // case data while the user is away.
        let app_state = app.state::<AppState>();
        let session = app_state.document_session().ok();

        let data_dir = app_state
            .data_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        // SEC: read settings flag (best effort) — when set, we suppress
        // titles/bodies even when the vault is unlocked.
        let (enabled, hide_preferences) = notification_preferences(&data_dir);
        if !enabled {
            continue;
        }
        let hide_details = session.is_none() || hide_preferences;

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
            fire_desktop_briefing(
                &app,
                time_str,
                items,
                &today,
                &tomorrow,
                hide_details,
                session,
            );
            eprintln!("[LexFlow Cron] ✓ Briefing fired: {}", briefing_key);
        }

        // Check per-item reminders — GROUP by fire minute to avoid notification spam
        fire_grouped_desktop_reminders(&app, items, &current_minute, hide_details, session);
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
    hide_details: bool,
    session: Option<crate::state::DocumentSession>,
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
    if hide_details {
        // PII-safe fallback: no titles, no bodies — just a generic alert.
        fire_urgent_desktop_notification(app, "LexFlow", "Hai un impegno", session);
        return;
    }
    let (title, body_str) =
        build_briefing_notification(items, filter_date, time_from, period_label);

    // Briefings are always time-sensitive (bypass DND)
    fire_urgent_desktop_notification(app, &title, &body_str, session);
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
fn fire_grouped_desktop_reminders(
    app: &AppHandle,
    items: &[Value],
    current_minute: &str,
    hide_details: bool,
    session: Option<crate::state::DocumentSession>,
) {
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
        let Some(remind_time) = compute_remind_time(item, item_local) else {
            continue;
        };
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

    // PII-safe fallback when vault is locked or user opted in.
    if hide_details {
        fire_urgent_desktop_notification(app, "LexFlow", "Hai un impegno", session);
        eprintln!(
            "[LexFlow Cron] ✓ Reminder fired (PII-safe, {} events suppressed)",
            matching.len()
        );
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
        let Some(remind_time) = compute_remind_time(item, item_local) else {
            return;
        };
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
        fire_urgent_desktop_notification(app, notif_title, &body, session);
        eprintln!("[LexFlow Cron] Reminder fired (1 event)");
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

        fire_urgent_desktop_notification(app, &notif_title, &body, session);
        eprintln!(
            "[LexFlow Cron] ✓ Grouped reminder fired: {} events in one notification",
            total
        );
    }
}

// ═══════════════════════════════════════════════════════════
//  DESKTOP CRON NOTIFICATION DELIVERY (tauri_plugin_notification)
// ═══════════════════════════════════════════════════════════
//
// NOTE: On macOS, when the user has Focus Mode (Do Not Disturb) enabled,
// regular notifications are silenced. For a legal app, missing a court
// deadline because of DND is unacceptable. The user must add LexFlow to
// their Focus Mode allowed apps in System Settings → Focus → LexFlow.

/// Fire a desktop notification on macOS / Windows / Linux.
/// Used by the desktop cron job for ALL events (briefings, reminders).
/// Uses tauri_plugin_notification via run_on_main_thread.
#[cfg(any(test, not(any(target_os = "android", target_os = "ios"))))]
fn notification_delivery_content<'a>(
    state: &AppState,
    session: Option<crate::state::DocumentSession>,
    hide_details: bool,
    title: &'a str,
    body: &'a str,
) -> (&'a str, &'a str) {
    if hide_details
        || session.is_none_or(|session| state.validate_document_session(session).is_err())
    {
        ("LexFlow", "Hai un impegno")
    } else {
        (title, body)
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn fire_urgent_desktop_notification(
    app: &AppHandle,
    title: &str,
    body: &str,
    session: Option<crate::state::DocumentSession>,
) {
    let t = zeroize::Zeroizing::new(title.to_string());
    let b = zeroize::Zeroizing::new(body.to_string());
    let app_clone = app.clone();
    let _ = app.run_on_main_thread(move || {
        use tauri_plugin_notification::NotificationExt;
        let state = app_clone.state::<AppState>();
        let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
        let dir = state
            .data_dir
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let (enabled, hide_details) = notification_preferences(&dir);
        if !enabled {
            return;
        }
        // The callback may run after autolock, another unlock, or a preference change.
        let (title, body) = notification_delivery_content(&state, session, hide_details, &t, &b);
        if let Err(e) = app_clone
            .notification()
            .builder()
            .title(title)
            .body(body)
            .show()
        {
            eprintln!("[LexFlow] Cron notification failed: {:?}", e);
        }
    });
}

#[cfg(test)]
mod privacy_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn future_briefings_use_their_delivery_date_including_year_rollover() {
        let scheduled_today = chrono::NaiveDate::from_ymd_opt(2026, 12, 30).unwrap();
        let delivery_day = scheduled_today.succ_opt().unwrap();
        assert_eq!(
            briefing_filter_params(8, delivery_day).unwrap(),
            ("2026-12-31".into(), "00:00", "oggi")
        );
        assert_eq!(
            briefing_filter_params(14, delivery_day).unwrap(),
            ("2026-12-31".into(), "13:00", "questo pomeriggio")
        );
        assert_eq!(
            briefing_filter_params(19, delivery_day).unwrap(),
            ("2027-01-01".into(), "00:00", "domani")
        );
    }

    #[test]
    fn notification_schedule_rejects_malformed_or_unbounded_reminders() {
        let valid = json!({"briefingTimes":["08:30"],"items":[{
            "id":"synthetic", "title":"Impegno sintetico", "date":"2026-09-08",
            "time":"09:00", "remindMinutes":30, "customRemindTime":null
        }]});
        assert!(valid_notification_schedule(&valid));
        for bad in [
            json!(i64::MAX),
            json!(i64::MIN),
            json!(-1),
            json!(20161),
            json!("30"),
            json!(0.5),
        ] {
            let mut schedule = valid.clone();
            schedule["items"][0]["remindMinutes"] = bad;
            assert!(!valid_notification_schedule(&schedule));
        }
        let mut invalid = valid.clone();
        invalid["items"][0]["date"] = json!("2026-02-31");
        assert!(!valid_notification_schedule(&invalid));
        invalid = valid.clone();
        invalid["briefingTimes"] = json!(["25:00"]);
        assert!(!valid_notification_schedule(&invalid));
        invalid = valid.clone();
        invalid["items"] = json!(vec![valid["items"][0].clone(); MAX_SCHEDULE_ITEMS + 1]);
        assert!(!valid_notification_schedule(&invalid));
        assert!(!valid_notification_schedule(
            &json!({"items":[],"briefingTimes":"08:30"})
        ));
    }

    #[test]
    fn extreme_reminder_minutes_never_panic_even_with_custom_time() {
        let base = json!({"date":"2026-09-08", "time":"09:00"});
        let item_local = parse_item_datetime(&base).unwrap();
        for minutes in [i64::MIN, -1, MAX_REMIND_MINUTES + 1, i64::MAX] {
            for custom in [json!(null), json!("08:30")] {
                let mut item = base.clone();
                item["remindMinutes"] = json!(minutes);
                item["customRemindTime"] = custom;
                assert!(compute_remind_time(&item, item_local).is_none());
            }
        }
        assert_eq!(
            (item_local - compute_remind_time(&base, item_local).unwrap()).num_minutes(),
            30
        );
        let mut custom = base.clone();
        custom["customRemindTime"] = json!("08:00");
        assert_eq!(
            (item_local - compute_remind_time(&custom, item_local).unwrap()).num_minutes(),
            60
        );
    }

    #[test]
    fn disabled_notifications_and_late_delivery_fail_closed() {
        assert!(notifications_enabled_by_settings(&json!({})));
        assert!(!notifications_enabled_by_settings(
            &json!({"notifyEnabled":false})
        ));
        assert!(!notifications_enabled_by_settings(
            &json!({"notifyEnabled":"true"})
        ));
        let directory = tempfile::tempdir().unwrap();
        let state = AppState::new(directory.path().into(), directory.path().into());
        *state.vault_dek.lock().unwrap() = Some(crate::state::SecureKey::new(
            zeroize::Zeroizing::new(vec![4; 32]),
        ));
        let session = state.document_session().unwrap();
        let confidential = ("LexFlow — promemoria", "Cliente sintetico riservato");
        assert_eq!(
            notification_delivery_content(
                &state,
                Some(session),
                false,
                confidential.0,
                confidential.1
            ),
            confidential
        );
        assert_eq!(
            notification_delivery_content(
                &state,
                Some(session),
                true,
                confidential.0,
                confidential.1
            ),
            ("LexFlow", "Hai un impegno")
        );
        state.lock_vault();
        for reunlock in [false, true] {
            if reunlock {
                *state.vault_dek.lock().unwrap() = Some(crate::state::SecureKey::new(
                    zeroize::Zeroizing::new(vec![4; 32]),
                ));
            }
            assert_eq!(
                notification_delivery_content(
                    &state,
                    Some(session),
                    false,
                    confidential.0,
                    confidential.1
                ),
                ("LexFlow", "Hai un impegno")
            );
        }
    }

    #[test]
    fn details_are_hidden_unless_explicitly_enabled() {
        assert!(details_hidden_by_settings(&json!({})));
        assert!(details_hidden_by_settings(
            &json!({"hide_notification_details": "false"})
        ));
        assert!(details_hidden_by_settings(
            &json!({"hide_notification_details": true})
        ));
        assert!(!details_hidden_by_settings(
            &json!({"hide_notification_details": false})
        ));
    }

    #[test]
    fn scheduled_notifications_preserve_timing_without_case_titles() {
        let mut schedule = json!({"items": [{"title": "Cliente riservato Rossi", "date": "2026-09-06", "time": "09:00", "category": "udienza"}]});
        redact_scheduled_titles(&mut schedule);
        assert_eq!(schedule["items"][0]["title"], "Impegno riservato");
        assert_eq!(schedule["items"][0]["time"], "09:00");
        assert!(!schedule.to_string().contains("Rossi"));
    }
}
