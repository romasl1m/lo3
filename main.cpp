#include "crow.h"
#include <sqlite3.h>
#include <crypt.h>
#include <string>
#include <fstream>
#include <mutex>
#include <sstream>
#include <random>
#include <unordered_map>
#include <vector>
#include <set>
#include <algorithm>
#include <cctype>
#include <cstdlib>

struct User {
    int id;
    std::string name;
    std::string code;
    std::string role;
};

static bool is_valid_code(const std::string &c) {
    if (c.size() < 3 or c.size() > 4)
        return false;
    if (c[0] != '0' and (c[0] < '1' or c[0] > '4'))
        return false;
    if (c[1] < 'A' or c[1] > 'E')
        return false;
    int num = 0;
    for (size_t i = 2; i < c.size(); i++) {
        if (c[i] < '0' or c[i] > '9')
            return false;
        num = num * 10 + (c[i] - '0');
    }
    return num >= 1 and num <= 35;
}

static sqlite3 *g_db = nullptr;
static std::mutex g_mutex;
static std::unordered_map<std::string, int> g_sessions;

static std::string generate_salt() {
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);
    std::string salt = "$6$";
    for (int i = 0; i < 16; i++)
        salt += charset[dis(gen)];
    salt += "$";
    return salt;
}

static std::string hash_password(const std::string &password) {
    std::string salt = generate_salt();
    struct crypt_data data{};
    char *result = crypt_r(password.c_str(), salt.c_str(), &data);
    return result ? std::string(result) : "";
}

static bool verify_password(const std::string &password, const std::string &stored) {
    if (stored.empty()) return false;
    if (stored[0] != '$') return password == stored;
    struct crypt_data data{};
    char *result = crypt_r(password.c_str(), stored.c_str(), &data);
    return result && stored == result;
}

static std::string generate_token() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    std::ostringstream os;
    os << std::hex << dis(gen) << dis(gen);
    return os.str();
}

static std::string create_session(int user_id) {
    std::string token = generate_token();
    g_sessions[token] = user_id;
    return token;
}

static bool db_exec(const std::string &sql) {
    char *err = nullptr;
    int rc = sqlite3_exec(g_db, sql.c_str(), nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        CROW_LOG_ERROR << "SQL error: " << (err ? err : "unknown");
        sqlite3_free(err);
        return false;
    }
    return true;
}

static void init_db() {
    const char *db_path = std::getenv("DATABASE_PATH");
    sqlite3_open(db_path && *db_path ? db_path : "events.db", &g_db);
    db_exec("PRAGMA journal_mode=WAL");
    db_exec("PRAGMA foreign_keys=ON");

    db_exec(R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            code TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    )");

    db_exec(R"(
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic TEXT NOT NULL,
            description TEXT NOT NULL,
            time TEXT NOT NULL,
            organizer TEXT NOT NULL,
            max_people INTEGER NOT NULL,
            sala TEXT NOT NULL DEFAULT ''
        )
    )");

    db_exec(R"(
        CREATE TABLE IF NOT EXISTS registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(event_id, user_id)
        )
    )");

    db_exec(R"(
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    )");
    db_exec("INSERT OR IGNORE INTO settings (key, value) VALUES ('max_events_per_user', '3')");

    // Migration: add sala column if missing
    {
        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db, "PRAGMA table_info(events)", -1, &stmt, nullptr);
        bool has_sala = false;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string col = (const char *)sqlite3_column_text(stmt, 1);
            if (col == "sala") has_sala = true;
        }
        sqlite3_finalize(stmt);
        if (!has_sala)
            db_exec("ALTER TABLE events ADD COLUMN sala TEXT NOT NULL DEFAULT ''");
    }
}

static User get_user_by_id(int id) {
    User u{0, "", "", ""};
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(g_db, "SELECT id, name, code, role FROM users WHERE id=?", -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, id);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        u.id = sqlite3_column_int(stmt, 0);
        u.name = (const char *)sqlite3_column_text(stmt, 1);
        u.code = (const char *)sqlite3_column_text(stmt, 2);
        u.role = (const char *)sqlite3_column_text(stmt, 3);
    }
    sqlite3_finalize(stmt);
    return u;
}

static User get_user_by_code(const std::string &code) {
    User u{0, "", "", ""};
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(g_db, "SELECT id, name, code, role FROM users WHERE code=?", -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, code.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        u.id = sqlite3_column_int(stmt, 0);
        u.name = (const char *)sqlite3_column_text(stmt, 1);
        u.code = (const char *)sqlite3_column_text(stmt, 2);
        u.role = (const char *)sqlite3_column_text(stmt, 3);
    }
    sqlite3_finalize(stmt);
    return u;
}

static std::string get_password_hash(const std::string &code) {
    std::string hash;
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(g_db, "SELECT password_hash FROM users WHERE code=?", -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, code.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) == SQLITE_ROW)
        hash = (const char *)sqlite3_column_text(stmt, 0);
    sqlite3_finalize(stmt);
    return hash;
}

static int count_registered(int event_id) {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(g_db,
                       "SELECT COUNT(*) FROM registrations WHERE event_id=? AND status='registered'",
                       -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, event_id);
    sqlite3_step(stmt);
    int n = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

static void promote_waitlist(int event_id) {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(g_db, "SELECT max_people FROM events WHERE id=?", -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, event_id);
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return;
    }
    int max_p = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    int reg = count_registered(event_id);
    while (reg < max_p) {
        sqlite3_prepare_v2(g_db,
                           "SELECT id FROM registrations WHERE event_id=? AND status='waitlisted' ORDER BY id LIMIT 1",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, event_id);
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            break;
        }
        int rid = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);

        sqlite3_prepare_v2(g_db,
                           "UPDATE registrations SET status='registered' WHERE id=?",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, rid);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        reg++;
    }
}

static int get_max_events_per_user() {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(g_db, "SELECT value FROM settings WHERE key='max_events_per_user'",
                       -1, &stmt, nullptr);
    int val = 3;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        val = std::stoi((const char *)sqlite3_column_text(stmt, 0));
    sqlite3_finalize(stmt);
    return std::max(1, val);
}

static User get_current_user(const crow::request &req) {
    std::string cookie = req.get_header_value("Cookie");
    std::string token;
    auto pos = cookie.find("session=");
    if (pos != std::string::npos) {
        auto start = pos + 8;
        auto end = cookie.find(';', start);
        token = cookie.substr(start, end == std::string::npos ? end : end - start);
    }
    if (token.empty())
        return {0, "", "", ""};

    auto it = g_sessions.find(token);
    if (it == g_sessions.end())
        return {0, "", "", ""};

    return get_user_by_id(it->second);
}

static std::string get_event_time(int event_id) {
    std::string t;
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(g_db, "SELECT time FROM events WHERE id=?", -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, event_id);
    if (sqlite3_step(stmt) == SQLITE_ROW)
        t = (const char *)sqlite3_column_text(stmt, 0);
    sqlite3_finalize(stmt);
    return t;
}

static std::set<std::string> get_user_registered_times(int user_id) {
    std::set<std::string> times;
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(g_db,
        "SELECT e.time FROM registrations r JOIN events e ON r.event_id=e.id "
        "WHERE r.user_id=?",
        -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, user_id);
    while (sqlite3_step(stmt) == SQLITE_ROW)
        times.insert((const char *)sqlite3_column_text(stmt, 0));
    sqlite3_finalize(stmt);
    return times;
}

static std::string html_escape(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '&':
            out += "&amp;";
            break;
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        case '"':
            out += "&quot;";
            break;
        case '\'':
            out += "&#39;";
            break;
        default:
            out += c;
        }
    }
    return out;
}

static std::string nav_html(const User &u) {
    std::ostringstream os;
    os << R"(<!DOCTYPE html><html lang="pl"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="/static/style.css">
<title>Rejestracja na wydarzenia</title>
</head><body><nav><div class="nav-left">)";
    os << "<a class=\"nav-brand\" href=\"/\"><img src=\"/logo.png\" alt=\"LO3\"></a>";
    if (u.id) {
        os << "<a href=\"/\">Wydarzenia</a>";
        os << "<a href=\"/moje-wydarzenia\">Moje wydarzenia</a>";
        if (u.role == "admin")
            os << "<a href=\"/admin\">Panel admina</a>"
               << "<a href=\"/admin/users\">U\xC5\xBCytkownicy</a>";
        os << "<a href=\"/profil\">Profil</a>";
    }
    os << "</div><div class=\"nav-right\">";
    if (u.id) {
        os << "<span class=\"nav-user\">" << html_escape(u.name)
           << " [" << html_escape(u.code) << "]</span>"
           << "<div class=\"nav-divider\"></div>"
           << "<a href=\"/logout\">Wyloguj</a>";
    }
    os << "</div></nav><div class=\"container\">";
    return os.str();
}

static const std::string foot = "</div></body></html>";

static std::string badge(const std::string &text, const std::string &cls) {
    return "<span class=\"badge " + cls + "\">" + html_escape(text) + "</span>";
}

static std::string alert(const std::string &msg, const std::string &cls = "info") {
    return "<div class=\"alert alert-" + cls + "\">" + html_escape(msg) + "</div>";
}

static crow::response redirect(const std::string &url) {
    crow::response res(303);
    res.add_header("Location", url);
    return res;
}

static crow::response require_login() {
    return redirect("/login");
}

static crow::response require_admin() {
    return redirect("/");
}

int main() {
    init_db();

    crow::SimpleApp app;

    CROW_ROUTE(app, "/static/style.css")
    ([] {
        std::ifstream f("static/style.css");
        if (!f)
            return crow::response(404);
        std::string css((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
        crow::response res(css);
        res.add_header("Content-Type", "text/css");
        return res;
    });

    CROW_ROUTE(app, "/logo.png")
    ([] {
        std::ifstream f("logo.png", std::ios::binary);
        if (!f)
            return crow::response(404);
        std::string image((std::istreambuf_iterator<char>(f)),
                          std::istreambuf_iterator<char>());
        crow::response res(image);
        res.add_header("Content-Type", "image/png");
        return res;
    });

    // ============================================================
    // Login / Logout
    // ============================================================

    CROW_ROUTE(app, "/login")
    ([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (u.id)
            return redirect("/");

        std::ostringstream os;
        os << nav_html({});
        os << "<div class=\"login-logo\"><img src=\"/logo.png\" alt=\"LO3\"></div>"
           << "<h1>Logowanie</h1>"
           << "<div class=\"hint-box\">"
           << "<strong>Tw\xC3\xB3j identyfikator</strong> to kod w formacie: "
           << "cyfra (<strong>1-4</strong>), "
           << "litera (<strong>A-E</strong>), "
           << "numer (<strong>1-35</strong>).<br>"
           << "Przyk\xC5\x82"
              "ad: <code>3A17</code>, <code>1B5</code>, <code>4E30</code>"
           << "</div>"
           << "<form method=\"POST\" action=\"/login\">"
           << "<label>Tw\xC3\xB3j identyfikator</label>"
           << "<input name=\"code\" placeholder=\"np. 3A17\" required "
           << "pattern=\"[1-4][A-E]([1-9]|[12][0-9]|3[0-5])\" "
           << "title=\"Format: cyfra(1-4), litera(A-E), numer(1-35)\" "
           << "style=\"text-transform:uppercase\" autocomplete=\"username\">"
           << "<label>Has\xC5\x82o</label>"
           << "<input name=\"password\" type=\"password\" placeholder=\"Twoje has\xC5\x82o\" "
           << "required autocomplete=\"current-password\">"
           << "<button type=\"submit\" class=\"btn\">Zaloguj</button>"
           << "</form>";
        os << foot;
        return crow::response(os.str());
    });

    CROW_ROUTE(app, "/login").methods(crow::HTTPMethod::POST)([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto body = crow::query_string("?" + req.body);
        std::string code = body.get("code") ? body.get("code") : "";
        std::string password = body.get("password") ? body.get("password") : "";

        for (auto &c : code)
            c = std::toupper(c);

        std::string stored = get_password_hash(code);
        if (stored.empty() or not verify_password(password, stored)) {
            std::ostringstream os;
            os << nav_html({});
            os << "<div class=\"login-logo\"><img src=\"/logo.png\" alt=\"LO3\"></div>"
               << "<h1>Logowanie</h1>"
               << alert("Nieprawid\xC5\x82owy identyfikator lub has\xC5\x82o.", "error")
               << "<div class=\"hint-box\">"
               << "<strong>Tw\xC3\xB3j identyfikator</strong> to kod w formacie: "
               << "cyfra (<strong>1-4</strong>), "
               << "litera (<strong>A-E</strong>), "
               << "numer (<strong>1-35</strong>).<br>"
               << "Przyk\xC5\x82"
                  "ad: <code>3A17</code>, <code>1B5</code>, <code>4E30</code>"
               << "</div>"
               << "<form method=\"POST\" action=\"/login\">"
               << "<label>Tw\xC3\xB3j identyfikator</label>"
               << "<input name=\"code\" placeholder=\"np. 3A17\" required "
               << "pattern=\"[1-4][A-E]([1-9]|[12][0-9]|3[0-5])\" "
               << "title=\"Format: cyfra(1-4), litera(A-E), numer(1-35)\" "
               << "style=\"text-transform:uppercase\" autocomplete=\"username\">"
               << "<label>Has\xC5\x82o</label>"
               << "<input name=\"password\" type=\"password\" placeholder=\"Twoje has\xC5\x82o\" "
               << "required autocomplete=\"current-password\">"
               << "<button type=\"submit\" class=\"btn\">Zaloguj</button>"
               << "</form>";
            os << foot;
            return crow::response(os.str());
        }

        User u = get_user_by_code(code);
        std::string token = create_session(u.id);
        auto res = redirect("/");
        res.add_header("Set-Cookie", "session=" + token + "; Path=/; HttpOnly; SameSite=Strict");
        return res;
    });

    CROW_ROUTE(app, "/logout")
    ([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::string cookie = req.get_header_value("Cookie");
        auto pos = cookie.find("session=");
        if (pos != std::string::npos) {
            auto start = pos + 8;
            auto end = cookie.find(';', start);
            std::string token = cookie.substr(start, end == std::string::npos ? end : end - start);
            g_sessions.erase(token);
        }
        auto res = redirect("/login");
        res.add_header("Set-Cookie", "session=; Path=/; HttpOnly; Max-Age=0");
        return res;
    });

    // ============================================================
    // Events list (main page)
    // ============================================================

    CROW_ROUTE(app, "/")
    ([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (not u.id)
            return require_login();

        std::unordered_map<int, std::string> my_regs;
        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db,
            "SELECT event_id, status FROM registrations WHERE user_id=?",
            -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, u.id);
        while (sqlite3_step(stmt) == SQLITE_ROW)
            my_regs[sqlite3_column_int(stmt, 0)] =
                (const char *)sqlite3_column_text(stmt, 1);
        sqlite3_finalize(stmt);

        int max_ev = get_max_events_per_user();

        std::ostringstream os;
        os << nav_html(u);
        os << "<h1>Wydarzenia</h1>"
           << "<p class=\"page-sub\">Zaznacz wydarzenia, w kt\xC3\xB3rych chcesz wzi\xC4\x85\xC4\x87 udzia\xC5\x82 (maks. "
           << max_ev << "). "
           << "Nie mo\xC5\xBCna wybra\xC4\x87 dw\xC3\xB3"
              "ch w tym samym czasie.</p>"
           << "<form method=\"POST\" action=\"/register-multiple\" id=\"ef\">"
           << "<input type=\"hidden\" name=\"_s\" value=\"1\">";

        sqlite3_prepare_v2(g_db,
            "SELECT id, topic, description, time, organizer, max_people, sala "
            "FROM events ORDER BY time ASC, id ASC",
            -1, &stmt, nullptr);

        std::string last_time;
        bool any = false;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            any = true;
            int eid = sqlite3_column_int(stmt, 0);
            std::string topic = (const char *)sqlite3_column_text(stmt, 1);
            std::string desc = (const char *)sqlite3_column_text(stmt, 2);
            std::string time_str = (const char *)sqlite3_column_text(stmt, 3);
            std::string org = (const char *)sqlite3_column_text(stmt, 4);
            int maxp = sqlite3_column_int(stmt, 5);
            std::string sala = sqlite3_column_text(stmt, 6) ? (const char *)sqlite3_column_text(stmt, 6) : "";
            int reg = count_registered(eid);
            int spots = maxp - reg;

            auto it = my_regs.find(eid);
            bool is_mine = (it != my_regs.end());
            std::string my_status = is_mine ? it->second : "";

            std::string display_time = time_str;
            auto sp = time_str.find(' ');
            if (sp != std::string::npos)
                display_time = time_str.substr(sp + 1);

            if (time_str != last_time) {
                if (!last_time.empty()) os << "</div>";
                os << "<div class=\"time-group\">"
                   << "<div class=\"time-label\">Czas rozpocz\xC4\x99"
                      "cia: " << html_escape(display_time) << "</div>";
                last_time = time_str;
            }

            os << "<div class=\"event-pick" << (is_mine ? " on" : "") << "\">"
               << "<input type=\"checkbox\" name=\"events\" value=\"" << eid
               << "\" data-time=\"" << html_escape(time_str) << "\""
               << (is_mine ? " checked" : "") << ">"
               << "<div class=\"ep-body\">"
               << "<div class=\"ep-top\">"
               << "<span class=\"ep-title\">" << html_escape(topic) << "</span>"
               << "<a href=\"/event/" << eid << "\" class=\"ep-detail\">szczeg\xC3\xB3\xC5\x82y &rsaquo;</a>"
               << "</div>"
               << "<div class=\"ep-meta\">" << html_escape(org);
            if (!sala.empty())
                os << " &middot; Sala: " << html_escape(sala);
            os << " &middot; " << reg << "/" << maxp;
            if (spots > 0)
                os << " &middot; " << spots << " wolnych";
            else
                os << " &middot; <span class=\"ep-full\">pe\xC5\x82ne</span>";
            os << "</div>";
            if (!desc.empty())
                os << "<div class=\"ep-desc\">" << html_escape(desc) << "</div>";
            if (is_mine)
                os << "<div class=\"ep-status "
                   << (my_status == "registered" ? "ep-reg" : "ep-wait") << "\">"
                   << (my_status == "registered" ? "Zapisany" : "W kolejce") << "</div>";
            os << "</div></div>";
        }
        sqlite3_finalize(stmt);

        if (!last_time.empty()) os << "</div>";
        if (!any) os << "<p class=\"muted\">Brak wydarze\xC5\x84.</p>";

        os << "<div style=\"height:80px\"></div></form>"
           << "<div class=\"sel-bar\" id=\"sb\">"
           << "<span>Wybrano: <strong id=\"sc\">0</strong></span>"
           << "<button type=\"submit\" form=\"ef\" class=\"btn\">Zapisz si\xC4\x99</button>"
           << "</div>";

        os << "<script>\n!function(){\nvar mx=" << max_ev << R"(,
bs=document.querySelectorAll('input[name="events"]'),
    bar=document.getElementById('sb'),
    cnt=document.getElementById('sc');
function up(){
  var ts={},n=0;
  bs.forEach(function(b){if(b.checked){ts[b.dataset.time]=1;n++}});
  bs.forEach(function(b){
    var r=b.closest('.event-pick');
    if(!b.checked&&(ts[b.dataset.time]||n>=mx)){b.disabled=1;r.classList.add('off')}
    else{b.disabled=0;r.classList.remove('off')}
    r.classList.toggle('on',b.checked)
  });
  cnt.textContent=n+'/'+mx;
  bar.classList.toggle('vis',n>0)
}
bs.forEach(function(b){b.addEventListener('change',up)});
document.querySelectorAll('.event-pick').forEach(function(el){
  el.addEventListener('click',function(e){
    if(e.target.closest('a')||e.target.type==='checkbox')return;
    var cb=el.querySelector('input');
    if(cb.disabled)return;
    cb.checked=!cb.checked;
    cb.dispatchEvent(new Event('change'))
  })
});
up()
}()
</script>)";

        os << foot;
        return crow::response(os.str());
    });

    // ============================================================
    // Register multiple events
    // ============================================================

    CROW_ROUTE(app, "/register-multiple").methods(crow::HTTPMethod::POST)
    ([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id) return require_login();
        if (req.body.find("_s=1") == std::string::npos)
            return redirect("/");

        int max_ev = get_max_events_per_user();

        std::set<int> selected;
        {
            std::string b = req.body;
            size_t pos = 0;
            while (pos < b.size()) {
                size_t eq = b.find("events=", pos);
                if (eq == std::string::npos) break;
                if (eq > 0 && b[eq - 1] != '&') { pos = eq + 7; continue; }
                size_t vs = eq + 7;
                size_t ve = b.find('&', vs);
                std::string val = b.substr(vs, ve == std::string::npos ? std::string::npos : ve - vs);
                try { selected.insert(std::stoi(val)); } catch (...) {}
                if (ve == std::string::npos) break;
                pos = ve + 1;
            }
        }

        if ((int)selected.size() > max_ev)
            return redirect("/");

        // Server-side time conflict check
        std::set<std::string> selected_times;
        for (int eid : selected) {
            std::string t = get_event_time(eid);
            if (!t.empty()) {
                if (selected_times.count(t))
                    return redirect("/");
                selected_times.insert(t);
            }
        }

        std::unordered_map<int, std::string> current;
        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db,
            "SELECT event_id, status FROM registrations WHERE user_id=?",
            -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, u.id);
        while (sqlite3_step(stmt) == SQLITE_ROW)
            current[sqlite3_column_int(stmt, 0)] =
                (const char *)sqlite3_column_text(stmt, 1);
        sqlite3_finalize(stmt);

        for (int eid : selected) {
            if (current.count(eid)) continue;
            sqlite3_prepare_v2(g_db, "SELECT max_people FROM events WHERE id=?",
                               -1, &stmt, nullptr);
            sqlite3_bind_int(stmt, 1, eid);
            if (sqlite3_step(stmt) != SQLITE_ROW) { sqlite3_finalize(stmt); continue; }
            int maxp = sqlite3_column_int(stmt, 0);
            sqlite3_finalize(stmt);

            int reg = count_registered(eid);
            std::string status = (reg < maxp) ? "registered" : "waitlisted";

            sqlite3_prepare_v2(g_db,
                "INSERT OR IGNORE INTO registrations (event_id, user_id, status) VALUES (?, ?, ?)",
                -1, &stmt, nullptr);
            sqlite3_bind_int(stmt, 1, eid);
            sqlite3_bind_int(stmt, 2, u.id);
            sqlite3_bind_text(stmt, 3, status.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }

        for (auto &[eid, st] : current) {
            if (selected.count(eid)) continue;
            sqlite3_prepare_v2(g_db,
                "DELETE FROM registrations WHERE event_id=? AND user_id=?",
                -1, &stmt, nullptr);
            sqlite3_bind_int(stmt, 1, eid);
            sqlite3_bind_int(stmt, 2, u.id);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);

            if (st == "registered")
                promote_waitlist(eid);
        }

        return redirect("/");
    });

    // ============================================================
    // Event detail
    // ============================================================

    CROW_ROUTE(app, "/event/<int>")
    ([](const crow::request &req, int id) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db,
                           "SELECT topic, description, time, organizer, max_people, sala FROM events WHERE id=?",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            return crow::response(404, "Nie znaleziono wydarzenia");
        }

        std::string topic = (const char *)sqlite3_column_text(stmt, 0);
        std::string desc = (const char *)sqlite3_column_text(stmt, 1);
        std::string time = (const char *)sqlite3_column_text(stmt, 2);
        std::string org = (const char *)sqlite3_column_text(stmt, 3);
        int maxp = sqlite3_column_int(stmt, 4);
        std::string sala = sqlite3_column_text(stmt, 5) ? (const char *)sqlite3_column_text(stmt, 5) : "";
        sqlite3_finalize(stmt);

        int reg = count_registered(id);
        int spots = maxp - reg;

        std::string my_status;
        sqlite3_prepare_v2(g_db,
                           "SELECT status FROM registrations WHERE event_id=? AND user_id=?",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);
        sqlite3_bind_int(stmt, 2, u.id);
        if (sqlite3_step(stmt) == SQLITE_ROW)
            my_status = (const char *)sqlite3_column_text(stmt, 0);
        sqlite3_finalize(stmt);

        std::ostringstream os;
        os << nav_html(u);

        os << "<h1>" << html_escape(topic) << "</h1>"
           << "<p class=\"meta\">"
           << "<strong>Organizator:</strong> " << html_escape(org)
           << " &mdash; <strong>Czas rozpocz\xC4\x99"
              "cia:</strong> " << html_escape(time);
        if (!sala.empty())
            os << " &mdash; <strong>Sala:</strong> " << html_escape(sala);
        os << "</p>"
           << "<p>" << html_escape(desc) << "</p>"
           << "<p><strong>" << reg << "/" << maxp << "</strong> zapisanych. ";
        if (spots > 0)
            os << badge(std::to_string(spots) + " wolnych miejsc", "green");
        else
            os << badge("Pe\xC5\x82ne", "red");
        os << "</p>";

        if (my_status.empty()) {
            // Check time conflict before showing register button
            bool conflict = false;
            auto user_times = get_user_registered_times(u.id);
            if (user_times.count(time))
                conflict = true;

            if (conflict) {
                os << "<div class=\"alert alert-error\">Masz ju\xC5\xBC zapisane wydarzenie w tym samym czasie.</div>";
            } else {
                os << "<form method=\"POST\" action=\"/event/" << id << "/register\" class=\"inline-form\">"
                   << "<button type=\"submit\" class=\"btn\">"
                   << (spots > 0 ? "Zapisz si\xC4\x99 na wydarzenie" : "Do\xC5\x82\xC4\x85"
                                                                        "cz do kolejki")
                   << "</button></form>";
            }
        } else if (my_status == "registered") {
            os << "<div class=\"status-box ok\">"
               << "Jeste\xC5\x9B zapisany na to wydarzenie"
               << "<form method=\"POST\" action=\"/event/" << id << "/resign\" class=\"inline-form\">"
               << "<button type=\"submit\" class=\"btn btn-outline-danger btn-sm\">Zrezygnuj</button></form>"
               << "</div>";
        } else {
            sqlite3_prepare_v2(g_db,
                               "SELECT COUNT(*) FROM registrations WHERE event_id=? AND status='waitlisted' AND id < "
                               "(SELECT id FROM registrations WHERE event_id=? AND user_id=?)",
                               -1, &stmt, nullptr);
            sqlite3_bind_int(stmt, 1, id);
            sqlite3_bind_int(stmt, 2, id);
            sqlite3_bind_int(stmt, 3, u.id);
            sqlite3_step(stmt);
            int pos = sqlite3_column_int(stmt, 0) + 1;
            sqlite3_finalize(stmt);

            os << "<div class=\"status-box wait\">"
               << "Jeste\xC5\x9B #" << pos << " w kolejce"
               << "<form method=\"POST\" action=\"/event/" << id << "/resign\" class=\"inline-form\">"
               << "<button type=\"submit\" class=\"btn btn-outline-danger btn-sm\">Opu\xC5\x9B\xC4\x87 kolejk\xC4\x99</button></form>"
               << "</div>";
        }

        os << "<h2>Zapisani (" << reg << "/" << maxp << ")</h2><ol>";
        sqlite3_prepare_v2(g_db,
                           "SELECT u.name FROM registrations r JOIN users u ON r.user_id=u.id "
                           "WHERE r.event_id=? AND r.status='registered' ORDER BY r.id",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);
        bool has_any_reg = false;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            has_any_reg = true;
            os << "<li>" << html_escape((const char *)sqlite3_column_text(stmt, 0)) << "</li>";
        }
        sqlite3_finalize(stmt);
        os << "</ol>";
        if (!has_any_reg) os << "<p class=\"muted\">Nikt nie jest jeszcze zapisany.</p>";

        sqlite3_prepare_v2(g_db,
                           "SELECT COUNT(*) FROM registrations WHERE event_id=? AND status='waitlisted'",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);
        sqlite3_step(stmt);
        int wcount = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);

        if (wcount > 0) {
            os << "<h2>Kolejka oczekuj\xC4\x85"
                  "cych (" << wcount << ")</h2><ol>";
            sqlite3_prepare_v2(g_db,
                               "SELECT u.name FROM registrations r JOIN users u ON r.user_id=u.id "
                               "WHERE r.event_id=? AND r.status='waitlisted' ORDER BY r.id",
                               -1, &stmt, nullptr);
            sqlite3_bind_int(stmt, 1, id);
            while (sqlite3_step(stmt) == SQLITE_ROW)
                os << "<li>" << html_escape((const char *)sqlite3_column_text(stmt, 0)) << "</li>";
            sqlite3_finalize(stmt);
            os << "</ol>";
        }

        os << foot;
        return crow::response(os.str());
    });

    // ============================================================
    // Register for single event
    // ============================================================

    CROW_ROUTE(app, "/event/<int>/register").methods(crow::HTTPMethod::POST)([](const crow::request &req, int id) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db, "SELECT max_people, time FROM events WHERE id=?", -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            return crow::response(404);
        }
        int maxp = sqlite3_column_int(stmt, 0);
        std::string event_time = (const char *)sqlite3_column_text(stmt, 1);
        sqlite3_finalize(stmt);

        // Check if already registered
        sqlite3_prepare_v2(g_db,
                           "SELECT id FROM registrations WHERE event_id=? AND user_id=?",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);
        sqlite3_bind_int(stmt, 2, u.id);
        bool exists = sqlite3_step(stmt) == SQLITE_ROW;
        sqlite3_finalize(stmt);
        if (exists)
            return redirect("/event/" + std::to_string(id));

        // Check time conflict
        auto user_times = get_user_registered_times(u.id);
        if (user_times.count(event_time))
            return redirect("/event/" + std::to_string(id));

        int reg = count_registered(id);
        std::string status = (reg < maxp) ? "registered" : "waitlisted";

        sqlite3_prepare_v2(g_db,
                           "INSERT INTO registrations (event_id, user_id, status) VALUES (?, ?, ?)",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);
        sqlite3_bind_int(stmt, 2, u.id);
        sqlite3_bind_text(stmt, 3, status.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return redirect("/event/" + std::to_string(id));
    });

    // ============================================================
    // Resign from event
    // ============================================================

    CROW_ROUTE(app, "/event/<int>/resign").methods(crow::HTTPMethod::POST)([](const crow::request &req, int id) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db,
                           "SELECT status FROM registrations WHERE event_id=? AND user_id=?",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);
        sqlite3_bind_int(stmt, 2, u.id);
        std::string status;
        if (sqlite3_step(stmt) == SQLITE_ROW)
            status = (const char *)sqlite3_column_text(stmt, 0);
        sqlite3_finalize(stmt);

        if (status.empty())
            return redirect("/event/" + std::to_string(id));

        sqlite3_prepare_v2(g_db,
                           "DELETE FROM registrations WHERE event_id=? AND user_id=?",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);
        sqlite3_bind_int(stmt, 2, u.id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (status == "registered")
            promote_waitlist(id);

        return redirect("/event/" + std::to_string(id));
    });

    // ============================================================
    // My events (Moje wydarzenia)
    // ============================================================

    CROW_ROUTE(app, "/moje-wydarzenia")
    ([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();

        std::ostringstream os;
        os << nav_html(u);
        os << "<h1>Moje wydarzenia</h1>";

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db,
            "SELECT e.id, e.topic, e.time, e.sala, e.organizer, r.status "
            "FROM registrations r JOIN events e ON r.event_id=e.id "
            "WHERE r.user_id=? ORDER BY e.time ASC",
            -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, u.id);

        bool any = false;
        os << "<table><tr><th>Wydarzenie</th><th>Czas rozpocz\xC4\x99"
              "cia</th><th>Sala</th><th>Organizator</th><th>Status</th></tr>";
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            any = true;
            int eid = sqlite3_column_int(stmt, 0);
            std::string topic = (const char *)sqlite3_column_text(stmt, 1);
            std::string time_str = (const char *)sqlite3_column_text(stmt, 2);
            std::string sala = sqlite3_column_text(stmt, 3) ? (const char *)sqlite3_column_text(stmt, 3) : "";
            std::string org = (const char *)sqlite3_column_text(stmt, 4);
            std::string st = (const char *)sqlite3_column_text(stmt, 5);

            os << "<tr>"
               << "<td><a href=\"/event/" << eid << "\">" << html_escape(topic) << "</a></td>"
               << "<td>" << html_escape(time_str) << "</td>"
               << "<td>" << html_escape(sala) << "</td>"
               << "<td>" << html_escape(org) << "</td>"
               << "<td>" << badge(st == "registered" ? "Zapisany" : "W kolejce",
                                   st == "registered" ? "green" : "yellow") << "</td>"
               << "</tr>";
        }
        sqlite3_finalize(stmt);
        os << "</table>";

        if (!any)
            os << "<p class=\"muted\">Nie jeste\xC5\x9B zapisany na \xC5\xBC"
                  "adne wydarzenie.</p>";

        os << foot;
        return crow::response(os.str());
    });

    // ============================================================
    // Profile (name + password change)
    // ============================================================

    CROW_ROUTE(app, "/profil")
    ([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();

        std::ostringstream os;
        os << nav_html(u);
        os << "<h1>Profil</h1>";

        os << "<div class=\"section-box\">"
           << "<h2>Zmie\xC5\x84 imi\xC4\x99 i nazwisko</h2>"
           << "<form method=\"POST\" action=\"/profil/name\">"
           << "<label>Imi\xC4\x99 i nazwisko</label>"
           << "<input name=\"name\" value=\"" << html_escape(u.name) << "\" required minlength=\"1\" placeholder=\"Jan Kowalski\">"
           << "<button type=\"submit\" class=\"btn\">Zapisz</button>"
           << "</form></div>";

        os << "<div class=\"section-box\">"
           << "<h2>Zmie\xC5\x84 has\xC5\x82o</h2>"
           << "<form method=\"POST\" action=\"/profil/password\">"
           << "<label>Obecne has\xC5\x82o</label>"
           << "<input name=\"old_password\" type=\"password\" required autocomplete=\"current-password\">"
           << "<label>Nowe has\xC5\x82o</label>"
           << "<input name=\"new_password\" type=\"password\" required minlength=\"1\" autocomplete=\"new-password\">"
           << "<label>Powt\xC3\xB3rz nowe has\xC5\x82o</label>"
           << "<input name=\"confirm_password\" type=\"password\" required minlength=\"1\" autocomplete=\"new-password\">"
           << "<button type=\"submit\" class=\"btn\">Zmie\xC5\x84 has\xC5\x82o</button>"
           << "</form></div>";

        os << foot;
        return crow::response(os.str());
    });

    CROW_ROUTE(app, "/profil/name").methods(crow::HTTPMethod::POST)([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();

        auto body = crow::query_string("?" + req.body);
        std::string new_name = body.get("name") ? body.get("name") : "";

        std::ostringstream os;
        os << nav_html(u);
        os << "<h1>Profil</h1>";

        if (new_name.empty()) {
            os << alert("Imi\xC4\x99 nie mo\xC5\xBC" "e by\xC4\x87 puste.", "error");
        } else {
            sqlite3_stmt *stmt;
            sqlite3_prepare_v2(g_db,
                               "UPDATE users SET name=? WHERE id=?",
                               -1, &stmt, nullptr);
            sqlite3_bind_text(stmt, 1, new_name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 2, u.id);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);

            u.name = new_name;
            os << alert("Imi\xC4\x99 zosta\xC5\x82o zmienione.", "info");
        }

        os << "<div class=\"section-box\">"
           << "<h2>Zmie\xC5\x84 imi\xC4\x99 i nazwisko</h2>"
           << "<form method=\"POST\" action=\"/profil/name\">"
           << "<label>Imi\xC4\x99 i nazwisko</label>"
           << "<input name=\"name\" value=\"" << html_escape(u.name) << "\" required minlength=\"1\" placeholder=\"Jan Kowalski\">"
           << "<button type=\"submit\" class=\"btn\">Zapisz</button>"
           << "</form></div>";

        os << "<div class=\"section-box\">"
           << "<h2>Zmie\xC5\x84 has\xC5\x82o</h2>"
           << "<form method=\"POST\" action=\"/profil/password\">"
           << "<label>Obecne has\xC5\x82o</label>"
           << "<input name=\"old_password\" type=\"password\" required autocomplete=\"current-password\">"
           << "<label>Nowe has\xC5\x82o</label>"
           << "<input name=\"new_password\" type=\"password\" required minlength=\"1\" autocomplete=\"new-password\">"
           << "<label>Powt\xC3\xB3rz nowe has\xC5\x82o</label>"
           << "<input name=\"confirm_password\" type=\"password\" required minlength=\"1\" autocomplete=\"new-password\">"
           << "<button type=\"submit\" class=\"btn\">Zmie\xC5\x84 has\xC5\x82o</button>"
           << "</form></div>";

        os << foot;
        return crow::response(os.str());
    });

    CROW_ROUTE(app, "/profil/password").methods(crow::HTTPMethod::POST)([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();

        auto body = crow::query_string("?" + req.body);
        std::string old_pass = body.get("old_password") ? body.get("old_password") : "";
        std::string new_pass = body.get("new_password") ? body.get("new_password") : "";
        std::string confirm = body.get("confirm_password") ? body.get("confirm_password") : "";

        std::string stored = get_password_hash(u.code);

        std::ostringstream os;
        os << nav_html(u);
        os << "<h1>Profil</h1>";

        if (!verify_password(old_pass, stored)) {
            os << alert("Nieprawid\xC5\x82owe obecne has\xC5\x82o.", "error");
        } else if (new_pass.size() < 1) {
            os << alert("Nowe has\xC5\x82o nie mo\xC5\xBC" "e by\xC4\x87 puste.", "error");
        } else if (new_pass != confirm) {
            os << alert("Nowe has\xC5\x82"
                        "a nie s\xC4\x85 zgodne.", "error");
        } else {
            std::string h = hash_password(new_pass);
            sqlite3_stmt *stmt;
            sqlite3_prepare_v2(g_db,
                               "UPDATE users SET password_hash=? WHERE id=?",
                               -1, &stmt, nullptr);
            sqlite3_bind_text(stmt, 1, h.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 2, u.id);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);

            os << alert("Has\xC5\x82o zosta\xC5\x82o zmienione.", "info");
        }

        os << "<div class=\"section-box\">"
           << "<h2>Zmie\xC5\x84 imi\xC4\x99 i nazwisko</h2>"
           << "<form method=\"POST\" action=\"/profil/name\">"
           << "<label>Imi\xC4\x99 i nazwisko</label>"
           << "<input name=\"name\" value=\"" << html_escape(u.name) << "\" required minlength=\"1\" placeholder=\"Jan Kowalski\">"
           << "<button type=\"submit\" class=\"btn\">Zapisz</button>"
           << "</form></div>";

        os << "<div class=\"section-box\">"
           << "<h2>Zmie\xC5\x84 has\xC5\x82o</h2>"
           << "<form method=\"POST\" action=\"/profil/password\">"
           << "<label>Obecne has\xC5\x82o</label>"
           << "<input name=\"old_password\" type=\"password\" required autocomplete=\"current-password\">"
           << "<label>Nowe has\xC5\x82o</label>"
           << "<input name=\"new_password\" type=\"password\" required minlength=\"1\" autocomplete=\"new-password\">"
           << "<label>Powt\xC3\xB3rz nowe has\xC5\x82o</label>"
           << "<input name=\"confirm_password\" type=\"password\" required minlength=\"1\" autocomplete=\"new-password\">"
           << "<button type=\"submit\" class=\"btn\">Zmie\xC5\x84 has\xC5\x82o</button>"
           << "</form></div>";

        os << foot;
        return crow::response(os.str());
    });

    // Keep old /password route as redirect
    CROW_ROUTE(app, "/password")
    ([](const crow::request &) {
        return redirect("/profil");
    });
    CROW_ROUTE(app, "/password").methods(crow::HTTPMethod::POST)([](const crow::request &) {
        return redirect("/profil");
    });

    // ============================================================
    // Admin routes
    // ============================================================

    CROW_ROUTE(app, "/admin")
    ([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();
        if (u.role != "admin")
            return require_admin();

        int max_ev = get_max_events_per_user();

        std::ostringstream os;
        os << nav_html(u);
        os << "<h1>Panel admina &mdash; Wydarzenia</h1>";

        os << "<div class=\"section-box\">"
           << "<h2>Limit zapis\xC3\xB3w</h2>"
           << "<form method=\"POST\" action=\"/admin/settings\" style=\"flex-direction:row;align-items:end;gap:10px\">"
           << "<div>"
           << "<label>Maks. wydarze\xC5\x84 na osob\xC4\x99</label>"
           << "<input name=\"max_events\" type=\"number\" min=\"1\" max=\"20\" value=\"" << max_ev << "\" required style=\"width:100px\">"
           << "</div>"
           << "<button type=\"submit\" class=\"btn btn-sm\">Zapisz</button>"
           << "</form></div>";

        os << "<h2>Utw\xC3\xB3rz wydarzenie</h2>"
           << "<form method=\"POST\" action=\"/admin/event\">"
           << "<label>Temat</label>"
           << "<input name=\"topic\" placeholder=\"Temat wydarzenia\" required>"
           << "<label>Opis</label>"
           << "<textarea name=\"description\" placeholder=\"O czym jest to wydarzenie?\" rows=\"3\" required></textarea>"
           << "<label>Czas rozpocz\xC4\x99"
              "cia</label>"
           << "<input name=\"time\" placeholder=\"2026-10-01 18:00\" required>"
           << "<label>Sala</label>"
           << "<input name=\"sala\" placeholder=\"np. 101, aula, sala gimnastyczna\">"
           << "<label>Organizator</label>"
           << "<input name=\"organizer\" placeholder=\"Imi\xC4\x99 i nazwisko\" required>"
           << "<label>Maksymalna liczba uczestnik\xC3\xB3w</label>"
           << "<input name=\"max_people\" type=\"number\" min=\"1\" placeholder=\"np. 30\" required>"
           << "<button type=\"submit\" class=\"btn\">Utw\xC3\xB3rz wydarzenie</button>"
           << "</form><hr>";

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db, "SELECT id, topic, max_people FROM events ORDER BY id DESC", -1, &stmt, nullptr);

        bool any = false;
        os << "<h2>Wszystkie wydarzenia</h2>";
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            any = true;
            int eid = sqlite3_column_int(stmt, 0);
            std::string topic = (const char *)sqlite3_column_text(stmt, 1);
            int maxp = sqlite3_column_int(stmt, 2);
            int reg = count_registered(eid);

            sqlite3_stmt *ws;
            sqlite3_prepare_v2(g_db,
                               "SELECT COUNT(*) FROM registrations WHERE event_id=? AND status='waitlisted'",
                               -1, &ws, nullptr);
            sqlite3_bind_int(ws, 1, eid);
            sqlite3_step(ws);
            int wcount = sqlite3_column_int(ws, 0);
            sqlite3_finalize(ws);

            os << "<div class=\"card\">"
               << "<h3>" << html_escape(topic) << "</h3>"
               << "<p>" << reg << "/" << maxp << " zapisanych";
            if (wcount > 0) os << ", " << wcount << " w kolejce";
            os << "</p>"
               << "<a class=\"btn btn-sm\" href=\"/admin/event/" << eid << "\">Zarz\xC4\x85"
                  "dzaj</a>"
               << "</div>";
        }
        sqlite3_finalize(stmt);
        if (!any)
            os << "<p class=\"muted\">Brak wydarze\xC5\x84.</p>";

        os << foot;
        return crow::response(os.str());
    });

    CROW_ROUTE(app, "/admin/settings").methods(crow::HTTPMethod::POST)
    ([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id) return require_login();
        if (u.role != "admin") return require_admin();

        auto body = crow::query_string("?" + req.body);
        int val = body.get("max_events") ? std::max(1, std::stoi(body.get("max_events"))) : 3;

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db,
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('max_events_per_user', ?)",
            -1, &stmt, nullptr);
        std::string sv = std::to_string(val);
        sqlite3_bind_text(stmt, 1, sv.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return redirect("/admin");
    });

    CROW_ROUTE(app, "/admin/event").methods(crow::HTTPMethod::POST)([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();
        if (u.role != "admin")
            return require_admin();

        auto body = crow::query_string("?" + req.body);
        std::string topic = body.get("topic") ? body.get("topic") : "";
        std::string desc = body.get("description") ? body.get("description") : "";
        std::string time = body.get("time") ? body.get("time") : "";
        std::string sala = body.get("sala") ? body.get("sala") : "";
        std::string org = body.get("organizer") ? body.get("organizer") : "";
        int maxp = body.get("max_people") ? std::max(1, std::stoi(body.get("max_people"))) : 1;

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db,
                           "INSERT INTO events (topic, description, time, organizer, max_people, sala) VALUES (?, ?, ?, ?, ?, ?)",
                           -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, topic.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, desc.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, time.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, org.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 5, maxp);
        sqlite3_bind_text(stmt, 6, sala.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return redirect("/admin");
    });

    CROW_ROUTE(app, "/admin/event/<int>")
    ([](const crow::request &req, int id) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();
        if (u.role != "admin")
            return require_admin();

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db,
                           "SELECT topic, description, time, organizer, max_people, sala FROM events WHERE id=?",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            return crow::response(404);
        }

        std::string topic = (const char *)sqlite3_column_text(stmt, 0);
        std::string desc = (const char *)sqlite3_column_text(stmt, 1);
        std::string time = (const char *)sqlite3_column_text(stmt, 2);
        std::string org = (const char *)sqlite3_column_text(stmt, 3);
        int maxp = sqlite3_column_int(stmt, 4);
        std::string sala = sqlite3_column_text(stmt, 5) ? (const char *)sqlite3_column_text(stmt, 5) : "";
        sqlite3_finalize(stmt);

        int reg = count_registered(id);

        std::ostringstream os;
        os << nav_html(u);
        os << "<h1>" << html_escape(topic) << "</h1>"
           << "<p class=\"meta\">"
           << "<strong>Organizator:</strong> " << html_escape(org)
           << " &mdash; <strong>Czas rozpocz\xC4\x99"
              "cia:</strong> " << html_escape(time);
        if (!sala.empty())
            os << " &mdash; <strong>Sala:</strong> " << html_escape(sala);
        os << " &mdash; <strong>Maks:</strong> " << maxp << "</p>"
           << "<p>" << html_escape(desc) << "</p>";

        os << "<h2>Zapisani (" << reg << "/" << maxp << ")</h2>";
        sqlite3_prepare_v2(g_db,
                           "SELECT u.id, u.name, u.code FROM registrations r JOIN users u ON r.user_id=u.id "
                           "WHERE r.event_id=? AND r.status='registered' ORDER BY r.id",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);

        bool has_reg = false;
        os << "<table><tr><th>#</th><th>Nazwa</th><th>ID</th><th>Akcja</th></tr>";
        int i = 1;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            has_reg = true;
            int uid = sqlite3_column_int(stmt, 0);
            os << "<tr><td>" << i++ << "</td>"
               << "<td>" << html_escape((const char *)sqlite3_column_text(stmt, 1)) << "</td>"
               << "<td>" << html_escape((const char *)sqlite3_column_text(stmt, 2)) << "</td>"
               << "<td><form method=\"POST\" action=\"/admin/event/" << id << "/remove\" style=\"margin:0\">"
               << "<input type=\"hidden\" name=\"user_id\" value=\"" << uid << "\">"
               << "<button type=\"submit\" class=\"btn btn-danger btn-sm\">Usu\xC5\x84</button>"
               << "</form></td></tr>";
        }
        sqlite3_finalize(stmt);
        os << "</table>";
        if (!has_reg)
            os << "<p class=\"muted\">Nikt nie jest jeszcze zapisany.</p>";

        sqlite3_prepare_v2(g_db,
                           "SELECT u.id, u.name, u.code FROM registrations r JOIN users u ON r.user_id=u.id "
                           "WHERE r.event_id=? AND r.status='waitlisted' ORDER BY r.id",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);

        bool has_wait = false;
        std::ostringstream ws;
        ws << "<h2>Kolejka oczekuj\xC4\x85"
              "cych</h2><table><tr><th>#</th><th>Nazwa</th><th>ID</th></tr>";
        i = 1;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            has_wait = true;
            ws << "<tr><td>" << i++ << "</td>"
               << "<td>" << html_escape((const char *)sqlite3_column_text(stmt, 1)) << "</td>"
               << "<td>" << html_escape((const char *)sqlite3_column_text(stmt, 2)) << "</td></tr>";
        }
        sqlite3_finalize(stmt);
        ws << "</table>";
        if (has_wait)
            os << ws.str();

        os << "<h2>Edytuj wydarzenie</h2>"
           << "<form method=\"POST\" action=\"/admin/event/" << id << "/edit\">"
           << "<label>Temat</label>"
           << "<input name=\"topic\" value=\"" << html_escape(topic) << "\" required>"
           << "<label>Opis</label>"
           << "<textarea name=\"description\" rows=\"3\" required>" << html_escape(desc) << "</textarea>"
           << "<label>Czas rozpocz\xC4\x99"
              "cia</label>"
           << "<input name=\"time\" value=\"" << html_escape(time) << "\" required>"
           << "<label>Sala</label>"
           << "<input name=\"sala\" value=\"" << html_escape(sala) << "\">"
           << "<label>Organizator</label>"
           << "<input name=\"organizer\" value=\"" << html_escape(org) << "\" required>"
           << "<label>Maksymalna liczba uczestnik\xC3\xB3w</label>"
           << "<input name=\"max_people\" type=\"number\" min=\"1\" value=\"" << maxp << "\" required>"
           << "<button type=\"submit\" class=\"btn\">Zaktualizuj wydarzenie</button>"
           << "</form>"
           << "<hr>"
           << "<h2>Usu\xC5\x84 wydarzenie</h2>"
           << "<p>To usunie wydarzenie i wszystkie zapisy.</p>"
           << "<form method=\"POST\" action=\"/admin/event/" << id << "/delete\">"
           << "<button type=\"submit\" class=\"btn btn-danger\">Usu\xC5\x84 wydarzenie</button>"
           << "</form>";

        os << foot;
        return crow::response(os.str());
    });

    CROW_ROUTE(app, "/admin/event/<int>/edit").methods(crow::HTTPMethod::POST)([](const crow::request &req, int id) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();
        if (u.role != "admin")
            return require_admin();

        auto body = crow::query_string("?" + req.body);
        std::string sala = body.get("sala") ? body.get("sala") : "";

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db,
                           "UPDATE events SET topic=?, description=?, time=?, organizer=?, max_people=?, sala=? WHERE id=?",
                           -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, body.get("topic"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, body.get("description"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, body.get("time"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, body.get("organizer"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 5, std::max(1, std::stoi(body.get("max_people"))));
        sqlite3_bind_text(stmt, 6, sala.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 7, id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        promote_waitlist(id);

        return redirect("/admin/event/" + std::to_string(id));
    });

    CROW_ROUTE(app, "/admin/event/<int>/remove").methods(crow::HTTPMethod::POST)([](const crow::request &req, int id) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();
        if (u.role != "admin")
            return require_admin();

        auto body = crow::query_string("?" + req.body);
        int uid = body.get("user_id") ? std::stoi(body.get("user_id")) : 0;

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db,
                           "SELECT status FROM registrations WHERE event_id=? AND user_id=?",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);
        sqlite3_bind_int(stmt, 2, uid);
        std::string status;
        if (sqlite3_step(stmt) == SQLITE_ROW)
            status = (const char *)sqlite3_column_text(stmt, 0);
        sqlite3_finalize(stmt);

        sqlite3_prepare_v2(g_db,
                           "DELETE FROM registrations WHERE event_id=? AND user_id=?",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);
        sqlite3_bind_int(stmt, 2, uid);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (status == "registered")
            promote_waitlist(id);

        return redirect("/admin/event/" + std::to_string(id));
    });

    CROW_ROUTE(app, "/admin/event/<int>/delete").methods(crow::HTTPMethod::POST)([](const crow::request &req, int id) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();
        if (u.role != "admin")
            return require_admin();

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db, "DELETE FROM events WHERE id=?", -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return redirect("/admin");
    });

    // ============================================================
    // User management (admin only)
    // ============================================================

    CROW_ROUTE(app, "/admin/users")
    ([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();
        if (u.role != "admin")
            return require_admin();

        std::ostringstream os;
        os << nav_html(u);
        os << "<h1>Zarz\xC4\x85"
              "dzanie u\xC5\xBCytkownikami</h1>";

        os << "<h2>Dodaj u\xC5\xBCytkownika</h2>"
           << "<form method=\"POST\" action=\"/admin/users\">"
           << "<label>Imi\xC4\x99 i nazwisko</label>"
           << "<input name=\"name\" placeholder=\"Jan Kowalski\" required>"
           << "<label>Identyfikator</label>"
           << "<input name=\"code\" placeholder=\"np. 3A17\" required "
           << "pattern=\"[1-4][A-Ea-e]([1-9]|[12][0-9]|3[0-5])\" "
           << "title=\"Format: cyfra(1-4), litera(A-E), numer(1-35)\" style=\"text-transform:uppercase\">"
           << "<label>Has\xC5\x82o</label>"
           << "<input name=\"password\" type=\"password\" placeholder=\"Has\xC5\x82o\" required minlength=\"1\">"
           << "<label>Rola</label>"
           << "<select name=\"role\"><option value=\"user\">U\xC5\xBCytkownik</option><option value=\"admin\">Admin</option></select>"
           << "<button type=\"submit\" class=\"btn\">Dodaj u\xC5\xBCytkownika</button>"
           << "</form><hr>";

        os << "<h2>Wszyscy u\xC5\xBCytkownicy</h2>"
           << "<table><tr><th>ID</th><th>Nazwa</th><th>Kod</th><th>Rola</th><th>Akcja</th></tr>";

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db, "SELECT id, name, code, role FROM users ORDER BY id", -1, &stmt, nullptr);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int uid = sqlite3_column_int(stmt, 0);
            std::string name = (const char *)sqlite3_column_text(stmt, 1);
            std::string code = (const char *)sqlite3_column_text(stmt, 2);
            std::string role = (const char *)sqlite3_column_text(stmt, 3);
            os << "<tr><td>" << uid << "</td>"
               << "<td>" << html_escape(name) << "</td>"
               << "<td>" << html_escape(code) << "</td>"
               << "<td>" << badge(role, role == "admin" ? "yellow" : "green") << "</td>"
               << "<td>";
            os << "<a class=\"btn btn-sm\" href=\"/admin/users/" << uid << "/wydarzenia\">Wydarzenia</a> ";
            if (uid != u.id) {
                os << "<form method=\"POST\" action=\"/admin/users/" << uid << "/delete\" style=\"margin:0;display:inline\">"
                   << "<button type=\"submit\" class=\"btn btn-danger btn-sm\">Usu\xC5\x84</button></form>";
            } else {
                os << "<span class=\"muted\">ty</span>";
            }
            os << "</td></tr>";
        }
        sqlite3_finalize(stmt);
        os << "</table>";

        os << foot;
        return crow::response(os.str());
    });

    CROW_ROUTE(app, "/admin/users").methods(crow::HTTPMethod::POST)([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();
        if (u.role != "admin")
            return require_admin();

        auto body = crow::query_string("?" + req.body);
        std::string name = body.get("name") ? body.get("name") : "";
        std::string code = body.get("code") ? body.get("code") : "";
        for (auto &c : code)
            c = std::toupper(c);

        if (!is_valid_code(code))
            return redirect("/admin/users");
        std::string pass = body.get("password") ? body.get("password") : "";
        std::string role = body.get("role") ? body.get("role") : "user";

        if (role != "admin" && role != "user")
            role = "user";

        std::string h = hash_password(pass);

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db,
                           "INSERT INTO users (name, code, password_hash, role) VALUES (?, ?, ?, ?)",
                           -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, code.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, h.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, role.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return redirect("/admin/users");
    });

    CROW_ROUTE(app, "/admin/users/<int>/delete").methods(crow::HTTPMethod::POST)([](const crow::request &req, int uid) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();
        if (u.role != "admin")
            return require_admin();
        if (uid == u.id)
            return redirect("/admin/users");

        std::vector<int> events_to_promote;
        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db,
                           "SELECT event_id FROM registrations WHERE user_id=? AND status='registered'",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, uid);
        while (sqlite3_step(stmt) == SQLITE_ROW)
            events_to_promote.push_back(sqlite3_column_int(stmt, 0));
        sqlite3_finalize(stmt);

        sqlite3_prepare_v2(g_db, "DELETE FROM users WHERE id=?", -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, uid);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        for (auto it = g_sessions.begin(); it != g_sessions.end();) {
            if (it->second == uid)
                it = g_sessions.erase(it);
            else
                ++it;
        }

        for (int eid : events_to_promote)
            promote_waitlist(eid);

        return redirect("/admin/users");
    });

    // ============================================================
    // Admin: view user's events
    // ============================================================

    CROW_ROUTE(app, "/admin/users/<int>/wydarzenia")
    ([](const crow::request &req, int uid) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();
        if (u.role != "admin")
            return require_admin();

        User target = get_user_by_id(uid);
        if (!target.id)
            return crow::response(404, "Nie znaleziono u\xC5\xBCytkownika");

        std::ostringstream os;
        os << nav_html(u);
        os << "<h1>Wydarzenia u\xC5\xBCytkownika: " << html_escape(target.name)
           << " [" << html_escape(target.code) << "]</h1>";

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db,
            "SELECT e.id, e.topic, e.time, e.sala, e.organizer, r.status "
            "FROM registrations r JOIN events e ON r.event_id=e.id "
            "WHERE r.user_id=? ORDER BY e.time ASC",
            -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, uid);

        bool any = false;
        os << "<table><tr><th>Wydarzenie</th><th>Czas rozpocz\xC4\x99"
              "cia</th><th>Sala</th><th>Organizator</th><th>Status</th></tr>";
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            any = true;
            int eid = sqlite3_column_int(stmt, 0);
            std::string topic = (const char *)sqlite3_column_text(stmt, 1);
            std::string time_str = (const char *)sqlite3_column_text(stmt, 2);
            std::string sala = sqlite3_column_text(stmt, 3) ? (const char *)sqlite3_column_text(stmt, 3) : "";
            std::string org = (const char *)sqlite3_column_text(stmt, 4);
            std::string st = (const char *)sqlite3_column_text(stmt, 5);

            os << "<tr>"
               << "<td><a href=\"/admin/event/" << eid << "\">" << html_escape(topic) << "</a></td>"
               << "<td>" << html_escape(time_str) << "</td>"
               << "<td>" << html_escape(sala) << "</td>"
               << "<td>" << html_escape(org) << "</td>"
               << "<td>" << badge(st == "registered" ? "Zapisany" : "W kolejce",
                                   st == "registered" ? "green" : "yellow") << "</td>"
               << "</tr>";
        }
        sqlite3_finalize(stmt);
        os << "</table>";

        if (!any)
            os << "<p class=\"muted\">U\xC5\xBCytkownik nie jest zapisany na \xC5\xBC"
                  "adne wydarzenie.</p>";

        os << "<p><a href=\"/admin/users\">&larr; Powr\xC3\xB3t do u\xC5\xBCytkownik\xC3\xB3w</a></p>";
        os << foot;
        return crow::response(os.str());
    });

    const char *port_env = std::getenv("PORT");
    int port = port_env && *port_env ? std::stoi(port_env) : 8080;
    app.port(port).multithreaded().run();
}
