//! Sync with a Kemlock Server, or with a Vaultwarden or Bitwarden server. Connecting asks for a password (and, where the account has a
//! second step, a code) and says what it costs, so it is `ame vault sync connect` in a terminal, where the questions of the sign-in are
//! asked (a weak key, a second step, a recovery code), and so is accepting what the service stopped to ask about
//! (`ame vault sync now accept`). Hidden vaults are never offered it. The page shows what `sync-status` answers: `connected`, and then
//! `backend` (`kemlock` or `bitwarden`), `moved`, `address`, `email`, `linked`, `running`, `last_success_ms`, `kinds` and
//! `problem`, which is `{name, detail}`. Without a connection, or while the service has not answered, it says "Not connected".
//! The service picks the Kemlock API on its own when the server answers like a Kemlock Server, so the form has one choice only, off the
//! main path: to use the Bitwarden API of such a server anyway.

use std::rc::Rc;

use amethystora_ui::adw::prelude::*;
use amethystora_ui::{glib, gtk, i18n, t, ui};
use serde_json::{json, Value};

use super::{Page, Vault, Width};
use crate::list;
use crate::widgets::{self, btn, say};

pub struct SyncPage {
    vault: Rc<Vault>,
    root: gtk::ScrolledWindow,
    head_chip: gtk::Label,
    server: gtk::Box,
    conflicts: gtk::Box,
    columns: gtk::Box,
    /// The row of each kind with its choice, which is drawn again by every reload
    kinds: gtk::Box,
    /// What turning a kind On does, which depends on the kind of server
    note: gtk::Label,
    /// What the server cannot hold, said under the kinds
    caution: gtk::Box,
    me: std::cell::RefCell<std::rc::Weak<SyncPage>>,
}

/// The kinds the page lists, by the words the service knows them by
fn kind_names() -> [(&'static str, String); 6] {
    [
        ("passwords", t!("Passwords")),
        ("codes", t!("Authenticator codes")),
        ("backup-codes", t!("Backup codes")),
        ("keys", t!("Keys")),
        ("certificates", t!("Certificates")),
        ("files", t!("Protected files")),
    ]
}

fn kind_row(name: &str, state: &str, tone: &str) -> gtk::Box {
    let row = ui::hbox(8, &["sync-kind"]);
    let words = ui::line(name, &[]);
    words.set_hexpand(true);
    row.append(&words);
    row.append(&widgets::chip(state, tone));
    row
}

/// Whether the connection the status describes is to a Kemlock Server, through its own API
fn is_kemlock(status: &Value) -> bool {
    status["backend"] == json!("kemlock")
}

/// The kind of server a connection is to
fn backend_name(kemlock: bool) -> String {
    if kemlock { t!("Kemlock Server") } else { t!("Vaultwarden or Bitwarden") }
}

/// What turning a kind On does: `None` before a server is connected, when it depends on which kind of server it turns out to be
fn goes_note(backend: Option<bool>) -> String {
    match backend {
        Some(true) => t!("On: the Kemlock apps and web vault on your other devices open it as the item it is. The server's encryption is all that protects it. A file goes as the item's own file, up to 16 MiB."),
        Some(false) => t!("On: Bitwarden's apps and browser extension on your other devices open it. The server's encryption is all that protects it. What Bitwarden has no item type for, such as a key, a certificate or a file, goes as a plain secure note."),
        None => t!("Which kinds go depends on the server. A Kemlock Server takes every kind, all On, as items its own apps open. Vaultwarden or Bitwarden takes passwords, codes and backup codes; a key, a certificate or a file is Off until you turn it on, and goes as a plain secure note."),
    }
}

/// What each kind does before a server is connected: On for the three every server takes, and, for the rest, what a Kemlock Server does
fn idle_state(word: &str) -> (String, &'static str) {
    if matches!(word, "passwords" | "codes" | "backup-codes") { (t!("On"), "ok") } else { (t!("Off, On with Kemlock"), "") }
}

/// What the move to Kemlock's own items says, from the status's `moved`: started, or done and when
fn moved_words(moved: &Value) -> Option<String> {
    if !moved.is_object() {
        return None;
    }
    Some(match moved["finished_ms"].as_i64() {
        Some(at) => t!("On {date}, the vault's items were moved from their Bitwarden copies to Kemlock's own items. The Bitwarden copies stay on the server as they are, and are not updated any more.", date = list::long_date(at)),
        None => t!("The vault's items are being moved from their Bitwarden copies to Kemlock's own items. The Bitwarden copies stay on the server as they are, and are not updated any more."),
    })
}

/// The command the Connect button runs: the address, and `bitwarden` only when the person chose the Bitwarden API of the server
fn connect_command(address: &str, bitwarden_api: bool) -> Vec<String> {
    let mut command: Vec<String> = ["ame", "vault", "sync", "connect"].iter().map(|word| word.to_string()).collect();
    command.push(address.to_string());
    if bitwarden_api {
        command.push("bitwarden".to_string());
    }
    command
}

/// What the last run stopped on, in words, and whether the person can accept it (`ame vault sync now accept`)
fn problem_words(name: &str, count: u64) -> (String, bool) {
    match name {
        "many-gone" => (t!("{count, plural, one {# item has gone from the server, or been put in its trash.} other {# items have gone from the server, or been put in its trash.}} If you removed them there, accept it.", count = count), true),
        "many-new" => (t!("{count, plural, one {# item has come from the server.} other {# items have come from the server.}} If you added them there, accept it.", count = count), true),
        "unreachable" | "timeout" | "server-down" => (t!("The server did not answer. The vault goes on, and tries again later."), false),
        "untrusted" => (t!("The server's certificate is not trusted."), false),
        "rate-limited" => (t!("The server asks for fewer tries. Wait a while."), false),
        "login-expired" | "keys-changed" | "cannot-open" | "identity-changed" | "session-ended" => (t!("The login has to be proved again. Disconnect, and connect again."), false),
        "not-kemlock" => (t!("The server did not answer like a Kemlock Server."), false),
        "server-too-old" => (t!("This Kemlock Server is too old for the vault: it lacks what signing in needs."), false),
        "domain-differs" => (t!("The server is set up under another address than the one given, so it would refuse every request. Connect again with the address it was set up with."), false),
        "dpop-refused" | "dpop-nonce" => (t!("The server refused the vault's proof of who is asking. Check this computer's clock, and that the address is the one the server is set up under."), false),
        "sso-only" => (t!("This account signs in with single sign-on, which the vault does not do."), false),
        "account-refused" => (t!("The server refused this account: it may be disabled, or being deleted."), false),
        "wrong-password-or-server" => (t!("The master password is wrong, or this is not the server the account was set up on."), false),
        "enrol-needs-totp" => (t!("This account was made through Bitwarden's API and its only second step is not an authenticator app. Sign in to its web vault once first."), false),
        "second-step-refused" => (t!("The second step was refused. The code may be wrong or already used."), false),
        "keys-invalid" => (t!("The account's keys on the server do not check out. Nothing was kept."), false),
        "manifest-invalid" | "item-missing" | "item-rolled-back" | "item-resurrected" => (t!("What the server holds does not match what it signed before. Nothing was changed."), false),
        "manifest-rolled-back" => (t!("The server's signed list of items is older than one the vault saw. A server giving an old copy back is what that is, so nothing was changed."), false),
        "items-unlisted" => (t!("Items that no signed list names have waited for a day. If they are yours, accept them."), true),
        "files-bucket" => (t!("This server keeps files in a storage bucket, which the vault does not use."), false),
        "move-check" => (t!("What was moved did not read back as it was sent. The vault will send what differs again."), false),
        "bad-answer" => (t!("The server answered in a way the protocol does not allow."), false),
        "siblings" => (t!("This vault was changed on two servers at once. Open it in the Kemlock app to settle it."), false),
        "kdf-lowered" | "kdf-too-weak" => (t!("The server asks for less work to make the key than it did. Nothing was sent."), false),
        "local-unreadable" => (t!("Some items of the vault did not read, so nothing is sent. Restore the vault from a backup."), false),
        _ => (t!("The last sync stopped. `ame vault sync status` says why."), false),
    }
}

impl SyncPage {
    pub fn new(vault: &Rc<Vault>) -> Rc<dyn Page> {
        let page = ui::vbox(18, &["page"]);
        let head = ui::hbox(12, &["page-head"]);
        let title = widgets::h1(&t!("Sync"));
        title.set_hexpand(true);
        head.append(&title);
        let head_chip = widgets::chip(&t!("Not connected"), "");
        head.append(&head_chip);
        page.append(&head);
        let columns = ui::hbox(16, &[]);
        let server = widgets::card();
        server.set_hexpand(true);
        columns.append(&server);
        let goes = widgets::card();
        goes.set_hexpand(true);
        goes.append(&widgets::h2(&t!("What goes there")));
        let kinds = ui::vbox(8, &[]);
        goes.append(&kinds);
        let note = widgets::p(&goes_note(None), &["soft", "small"]);
        goes.append(&note);
        let caution = ui::vbox(6, &[]);
        goes.append(&caution);
        columns.append(&goes);
        page.append(&columns);
        let conflicts = ui::vbox(0, &[]);
        page.append(&conflicts);
        page.append(&widgets::p(&t!("The server sees only encrypted items, but it can try to trick an app. Use a server you trust, and keep your most sensitive items Off."), &["soft", "small"]));
        let root = gtk::ScrolledWindow::builder().hscrollbar_policy(gtk::PolicyType::Never).hexpand(true).vexpand(true).child(&page).build();
        let this = Rc::new(SyncPage { vault: vault.clone(), root, head_chip, server, conflicts, columns, kinds, note, caution, me: std::cell::RefCell::new(std::rc::Weak::new()) });
        this.me.replace(Rc::downgrade(&this));
        this.idle_kinds();
        this
    }

    /// Before a server is connected: what each kind will do once one is
    fn idle_kinds(&self) {
        ui::clear(&self.kinds);
        ui::clear(&self.caution);
        self.note.set_label(&goes_note(None));
        for (word, name) in kind_names() {
            let (state, tone) = idle_state(word);
            self.kinds.append(&kind_row(&name, &state, tone));
        }
        self.caution.append(&widgets::p(&t!("Bitwarden's own servers keep files at a storage host this vault does not use, so there only what fits one note or field syncs. Vaultwarden, or a server of your own, keeps everything."), &["soft", "small"]));
    }

    /// With a server: one row a kind, Off and On side by side, one click each. Each change is asked of the person by the
    /// service, once, and covers what is added later.
    fn connected_kinds(&self, status: &Value) {
        ui::clear(&self.kinds);
        ui::clear(&self.caution);
        let kemlock = is_kemlock(status);
        self.note.set_label(&goes_note(Some(kemlock)));
        for (word, name) in kind_names() {
            let row = ui::hbox(8, &["sync-kind"]);
            let words = ui::line(&name, &[]);
            words.set_hexpand(true);
            row.append(&words);
            let current = status["kinds"][word].as_str().unwrap_or("off").to_string();
            let vault = self.vault.clone();
            row.append(&widgets::seg(&[("off", t!("Off")), ("on", t!("On"))], &current, move |value| {
                let (vault, value) = (vault.clone(), value.to_string());
                glib::spawn_future_local(async move {
                    if let Err(trouble) = vault.call(json!({"op": "sync-kind", "kind": word, "choice": value})).await {
                        vault.say(&trouble.words());
                    }
                    vault.reload_current();
                });
            }));
            self.kinds.append(&row);
        }
        // A Kemlock Server keeps its files itself, so what Bitwarden's cloud and other servers cannot take is not said of it
        let cloud = !kemlock && status["address"].as_str().is_some_and(|address| address.contains("bitwarden.com") || address.contains("bitwarden.eu"));
        if cloud {
            self.caution.append(&widgets::p(&t!("Bitwarden's own servers keep files at a storage host this vault does not use, so here only what fits one note or field syncs. The rest stays on this computer."), &["warn", "small"]));
        }
        let why = match status["no_files"].as_str() {
            Some("attachments-premium") => Some(t!("This account has no premium, which Bitwarden's server asks for files. What does not fit a note stays on this computer.")),
            Some("attachments-refused") => Some(t!("This server does not take files, or the account's room for them is spent. What does not fit a note stays on this computer.")),
            Some("attachments-elsewhere") => Some(t!("This server keeps files at another host, which the vault never contacts. What does not fit a note stays on this computer.")),
            _ => None,
        };
        if let Some(words) = why.filter(|_| !cloud && !kemlock) {
            self.caution.append(&widgets::p(&words, &["warn", "small"]));
        }
    }

    fn not_connected(&self) {
        self.idle_kinds();
        let server = &self.server;
        ui::clear(server);
        server.append(&widgets::h2(&t!("Your server")));
        let address = widgets::entry("", "https://");
        address.set_direction(gtk::TextDirection::Ltr);
        server.append(&widgets::field(&t!("Address"), &address, &[]));
        server.append(&widgets::p(&t!("Whoever opens this vault can reach that whole account, so a dedicated account is best. Its address is named under what this computer sends. The login happens in a terminal, where a second step is asked too."), &["soft", "small"]));
        // Off the main path: a Kemlock Server is found by itself, and this is for using the Bitwarden API it also has
        let bitwarden_api = widgets::check(&t!("Use Bitwarden's API, even if this is a Kemlock Server"), false, |_| {});
        server.append(&bitwarden_api);
        let error = widgets::problem();
        server.append(&error);
        let vault = self.vault.clone();
        let connect = btn(&t!("Connect"), Some("refresh"), &["primary"], move || {
            let typed = address.text().trim().to_string();
            if !typed.starts_with("https://") {
                say(&error, &t!("The address starts with https://."));
                return;
            }
            say(&error, "");
            let command = connect_command(&typed, bitwarden_api.is_active());
            vault.in_terminal(&command.iter().map(String::as_str).collect::<Vec<_>>());
        });
        connect.set_halign(gtk::Align::Start);
        server.append(&connect);
    }

    fn connected(&self, status: &Value) {
        let server = &self.server;
        ui::clear(server);
        server.append(&widgets::h2(&t!("Your server")));
        let pairs = widgets::Pairs::new();
        pairs.add(&t!("Address"), status["address"].as_str().unwrap_or(""), true);
        pairs.add(&t!("Kind of server"), &backend_name(is_kemlock(status)), false);
        pairs.add(&t!("Account"), status["email"].as_str().unwrap_or(""), true);
        if let Some(linked) = status["linked"].as_u64() {
            pairs.add(&t!("Items kept in step"), &i18n::number(linked as f64), false);
        }
        if status["running"] == json!(true) {
            pairs.add(&t!("Now"), &t!("Syncing…"), false);
        } else if let Some(last) = status["last_success_ms"].as_i64().filter(|last| *last > 0) {
            pairs.add(&t!("Last sync"), &list::long_date(last), false);
        } else {
            pairs.add(&t!("Last sync"), &t!("Not yet"), false);
        }
        server.append(&pairs.grid);
        if let Some(words) = moved_words(&status["moved"]) {
            server.append(&widgets::p(&words, &["soft", "small"]));
        }
        let row = ui::hbox(8, &[]);
        let (now, off) = (self.vault.clone(), self.vault.clone());
        row.append(&btn(&t!("Sync now"), Some("refresh"), &["primary"], move || now.in_terminal(&["ame", "vault", "sync", "now"])));
        row.append(&btn(&t!("Disconnect"), None, &["danger"], move || off.in_terminal(&["ame", "vault", "sync", "off"])));
        server.append(&row);
        ui::clear(&self.conflicts);
        // What the last run did to items changed in both places: both were kept
        let report = &status["last"]["report"];
        let conflicts = report["conflicts"].as_u64().unwrap_or(0);
        // What the server was not sent, and so is on this computer only: said, never left to be found missing
        let refused = report["refused_total"].as_u64().unwrap_or(0);
        let problem = &status["problem"];
        if conflicts == 0 && refused == 0 && !problem.is_object() {
            return;
        }
        let card = widgets::card();
        card.append(&widgets::h2(&t!("Needs a look")));
        if conflicts > 0 {
            card.append(&ui::label(&t!("{count, plural, one {# item changed here and on the server. Both are kept.} other {# items changed here and on the server. Both are kept.}}", count = conflicts), &[]));
        }
        if refused > 0 {
            card.append(&ui::label(&t!("{count, plural, one {# item did not go to the server, and stays on this computer only. Its page says why.} other {# items did not go to the server, and stay on this computer only. Each one's page says why.}}", count = refused), &[]));
        }
        if let Some(name) = problem["name"].as_str() {
            let count = problem["detail"]["count"].as_u64().unwrap_or(0);
            let (words, accept) = problem_words(name, count);
            let said = ui::label(&words, &[]);
            said.set_hexpand(true);
            card.append(&said);
            // The service stopped to ask the person, and a person is who answers: in a terminal, where it is asked
            if accept {
                let vault = self.vault.clone();
                let button = btn(&t!("Accept it"), Some("check"), &["primary", "small"], move || vault.in_terminal(&["ame", "vault", "sync", "now", "accept"]));
                button.set_halign(gtk::Align::Start);
                card.append(&button);
            }
        }
        self.conflicts.append(&card);
    }
}

impl Page for SyncPage {
    fn widget(&self) -> gtk::Widget {
        self.root.clone().upcast()
    }

    fn reload(&self) {
        let (vault, weak) = (self.vault.clone(), self.me.borrow().clone());
        vault.clone().spawn(async move |_| {
            let status = vault.call(json!({"op": "sync-status"})).await;
            let Some(page) = weak.upgrade() else { return };
            match status {
                Ok(status) if status["connected"] == json!(true) => {
                    page.head_chip.set_label(&t!("Connected"));
                    page.head_chip.add_css_class("ok");
                    page.connected(&status);
                    page.connected_kinds(&status);
                }
                _ => {
                    page.head_chip.set_label(&t!("Not connected"));
                    page.head_chip.remove_css_class("ok");
                    page.not_connected();
                }
            }
        });
    }

    fn width(&self, width: Width) {
        self.columns.set_orientation(if width == Width::Full { gtk::Orientation::Horizontal } else { gtk::Orientation::Vertical });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_names_the_kind_of_server() {
        assert!(is_kemlock(&json!({"backend": "kemlock"})));
        assert!(!is_kemlock(&json!({"backend": "bitwarden"})));
        // A status from before the field existed is a Vaultwarden's or Bitwarden's
        assert!(!is_kemlock(&json!({"connected": true})));
        assert_ne!(backend_name(true), backend_name(false));
    }

    #[test]
    fn what_on_does_is_said_for_the_kind_of_server() {
        let (kemlock, bitwarden, unknown) = (goes_note(Some(true)), goes_note(Some(false)), goes_note(None));
        assert!(kemlock.contains("Kemlock") && !kemlock.contains("Bitwarden"));
        assert!(bitwarden.contains("Bitwarden") && !bitwarden.contains("Kemlock"));
        assert!(unknown.contains("Kemlock") && unknown.contains("Vaultwarden"));
    }

    #[test]
    fn before_a_server_every_kind_has_a_state() {
        assert_eq!(idle_state("passwords").1, "ok");
        assert_eq!(idle_state("files").1, "");
        for (word, _) in kind_names() {
            assert!(!idle_state(word).0.is_empty());
        }
        // The page lists exactly the kinds the service has
        let service: Vec<&str> = amethystora_vault_core::sync::kinds::ALL.iter().map(|(word, _)| *word).collect();
        let page: Vec<&str> = kind_names().iter().map(|(word, _)| *word).collect();
        assert_eq!(service, page);
    }

    #[test]
    fn the_move_is_said_started_and_done() {
        assert!(moved_words(&Value::Null).is_none());
        let started = moved_words(&json!({"started_ms": 1000, "finished_ms": null})).unwrap();
        let done = moved_words(&json!({"started_ms": 1000, "finished_ms": 1_700_000_000_000_i64})).unwrap();
        assert!(started.contains("being moved") && done.contains("were moved"));
        assert!(done.contains("not updated any more") && started.contains("not updated any more"));
    }

    #[test]
    fn the_connect_command_adds_only_the_choice_of_the_bitwarden_api() {
        assert_eq!(connect_command("https://v.example", false), ["ame", "vault", "sync", "connect", "https://v.example"]);
        assert_eq!(connect_command("https://v.example", true), ["ame", "vault", "sync", "connect", "https://v.example", "bitwarden"]);
    }

    #[test]
    fn every_word_the_service_stops_on_has_a_sentence_of_its_own() {
        let generic = problem_words("no-such-word", 0).0;
        for name in [
            "not-kemlock", "server-too-old", "domain-differs", "session-ended", "dpop-refused", "dpop-nonce", "sso-only", "account-refused", "wrong-password-or-server",
            "enrol-needs-totp", "keys-invalid", "keys-changed", "manifest-invalid", "manifest-rolled-back", "item-missing", "item-rolled-back", "item-resurrected", "items-unlisted",
            "files-bucket", "move-check", "second-step-refused", "bad-answer", "siblings",
        ] {
            assert_ne!(problem_words(name, 0).0, generic, "{name}");
        }
        // What the person can accept is only what the service stops to ask about
        assert!(problem_words("items-unlisted", 0).1 && problem_words("many-gone", 2).1 && !problem_words("session-ended", 0).1);
    }
}
