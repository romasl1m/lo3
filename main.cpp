#include "crow.h"
#include <sqlite3.h>
#include <crypt.h>
#include <string>
#include <mutex>
#include <sstream>
#include <random>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <cctype>

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
    sqlite3_open("events.db", &g_db);
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
            max_people INTEGER NOT NULL
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
}

static void seed_admins() {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(g_db, "SELECT COUNT(*) FROM users WHERE role='admin'", -1, &stmt, nullptr);
    sqlite3_step(stmt);
    int count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (count > 0)
        return;

    struct {
        const char *name;
        const char *code;
        const char *pass;
    } admins[] = {
        {"Admin One", "1A1", "admin123"},
        {"Admin Two", "1A2", "admin456"},
    };

    sqlite3_prepare_v2(g_db,
                       "INSERT INTO users (name, code, password_hash, role) VALUES (?, ?, ?, 'admin')",
                       -1, &stmt, nullptr);

    for (auto &a : admins) {
        std::string h = hash_password(a.pass);
        sqlite3_bind_text(stmt, 1, a.name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, a.code, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, h.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);

    CROW_LOG_INFO << "Seeded 2 admin accounts (1A1 / admin123, 1A2 / admin456)";
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

static User get_current_user(const crow::request &req) {
    std::string cookie
    = req.get_header_value("Cookie");
    std::string token;
    auto pos = cookie
    .find("session=");
    if (pos != std::string::npos) {
        auto start = pos + 8;
        auto end = cookie
        .find(';', start);
        token = cookie
        .substr(start, end == std::string::npos ? end : end - start);
    }
    if (token.empty())
        return {0, "", "", ""};

    auto it = g_sessions.find(token);
    if (it == g_sessions.end())
        return {0, "", "", ""};

    return get_user_by_id(it->second);
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
    os << R"(<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="/static/style.css">
<title>Event Registration</title>
</head><body><nav><div class="nav-left">)";
    os << "<a class=\"nav-brand\" href=\"/\">EventReg</a>";
    if (u.id) {
        os << "<a href=\"/\">Events</a>";
        if (u.role == "admin")
            os << "<a href=\"/admin\">Admin</a>"
               << "<a href=\"/admin/users\">Users</a>";
    }
    os << "</div><div class=\"nav-right\">";
    if (u.id) {
        os << "<span class=\"nav-user\">" << html_escape(u.name)
           << " [" << html_escape(u.code) << "]</span>"
           << "<div class=\"nav-divider\"></div>"
           << "<a href=\"/logout\">Logout</a>";
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
    seed_admins();

    crow::SimpleApp app;

    CROW_ROUTE(app, "/static/style.css")
    ([] {
        std::ifstream f("../static/style.css");
        if (!f)
            return crow::response(404);
        std::string css((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
        crow::response res(css);
        res.add_header("Content-Type", "text/css");
        return res;
    });

    CROW_ROUTE(app, "/login")
    ([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (u.id)
            return redirect("/");

        std::ostringstream os;
        os << nav_html({});
        os << "<h1>Login</h1>"
           << "<div class=\"hint-box\">"
           << "<strong>Your ID</strong> is a code in the format: "
           << "number (<strong>1-4</strong>), "
           << "letter (<strong>A-E</strong>), "
           << "number (<strong>1-35</strong>).<br>"
           << "Example: <code>3A17</code>, <code>1B5</code>, <code>4E30</code>"
           << "</div>"
           << "<form method=\"POST\" action=\"/login\">"
           << "<label>Your ID</label>"
           << "<input name=\"code\" placeholder=\"e.g. 3A17\" required "
           << "pattern=\"[1-4][A-E]([1-9]|[12][0-9]|3[0-5])\" "
           << "title=\"Format: digit(1-4), letter(A-E), number(1-35)\" "
           << "style=\"text-transform:uppercase\" autocomplete=\"username\">"
           << "<label>Password</label>"
           << "<input name=\"password\" type=\"password\" placeholder=\"Your password\" "
           << "required autocomplete=\"current-password\">"
           << "<button type=\"submit\" class=\"btn\">Login</button>"
           << "</form>";
        os << foot;
        return crow::response(os.str());
    });

    CROW_ROUTE(app, "/login").methods(crow::HTTPMethod::POST)([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto body = crow::query_string("?" + req.body);
        std::string code = body.get("code") ? body.get("code") : "";
        std::string password = body.get("password") ? body.get("password") : "";

        // Uppercase the code
        for (auto &c : code)
            c = std::toupper(c);

        std::string stored = get_password_hash(code);
        if (stored.empty() or not verify_password(password, stored)) {
            std::ostringstream os;
            os << nav_html({});
            os << "<h1>Login</h1>"
               << alert("Invalid ID or password.", "error")
               << "<div class=\"hint-box\">"
               << "<strong>Your ID</strong> is a code in the format: "
               << "number (<strong>1-4</strong>), "
               << "letter (<strong>A-E</strong>), "
               << "number (<strong>1-35</strong>).<br>"
               << "Example: <code>3A17</code>, <code>1B5</code>, <code>4E30</code>"
               << "</div>"
               << "<form method=\"POST\" action=\"/login\">"
               << "<label>Your ID</label>"
               << "<input name=\"code\" placeholder=\"e.g. 3A17\" required "
               << "pattern=\"[1-4][A-E]([1-9]|[12][0-9]|3[0-5])\" "
               << "title=\"Format: digit(1-4), letter(A-E), number(1-35)\" "
               << "style=\"text-transform:uppercase\" autocomplete=\"username\">"
               << "<label>Password</label>"
               << "<input name=\"password\" type=\"password\" placeholder=\"Your password\" "
               << "required autocomplete=\"current-password\">"
               << "<button type=\"submit\" class=\"btn\">Login</button>"
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
        std::string cookie
        = req.get_header_value("Cookie");
        auto pos = cookie
        .find("session=");
        if (pos != std::string::npos) {
            auto start = pos + 8;
            auto end = cookie
            .find(';', start);
            std::string token = cookie
            .substr(start, end == std::string::npos ? end : end - start);
            g_sessions.erase(token);
        }
        auto res = redirect("/login");
        res.add_header("Set-Cookie", "session=; Path=/; HttpOnly; Max-Age=0");
        return res;
    });

    CROW_ROUTE(app, "/")
    ([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (not u.id)
            return require_login();

        std::ostringstream os;
        os << nav_html(u);
        os << "<h1>Upcoming Events</h1>";

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db, "SELECT id, topic, description, time, organizer, max_people FROM events ORDER BY id DESC", -1, &stmt, nullptr);

        bool any = false;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            any = true;
            int eid = sqlite3_column_int(stmt, 0);
            std::string topic = (const char *)sqlite3_column_text(stmt, 1);
            std::string desc = (const char *)sqlite3_column_text(stmt, 2);
            std::string time = (const char *)sqlite3_column_text(stmt, 3);
            std::string org = (const char *)sqlite3_column_text(stmt, 4);
            int maxp = sqlite3_column_int(stmt, 5);
            int reg = count_registered(eid);
            int spots = maxp - reg;

            // Count waitlisted
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
               << "<p class=\"meta\">"
               << "<strong>Organizer:</strong> " << html_escape(org)
               << " &mdash; <strong>Time:</strong> " << html_escape(time) << "</p>"
               << "<p>" << html_escape(desc) << "</p>"
               << "<p>" << reg << "/" << maxp << " registered. ";
            if (spots > 0)
                os << badge(std::to_string(spots) + " spots left", "green");
            else
                os << badge("Full", "red")
                   << " " << badge(std::to_string(wcount) + " waiting", "yellow");
            os << "</p>"
               << "<a class=\"btn\" href=\"/event/" << eid << "\">View &amp; Register</a>"
               << "</div>";
        }
        sqlite3_finalize(stmt);

        if (!any)
            os << "<p class=\"muted\">No events yet.</p>";
        os << foot;
        return crow::response(os.str());
    });

    // --- Event detail ---
    CROW_ROUTE(app, "/event/<int>")
    ([](const crow::request &req, int id) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db,
                           "SELECT topic, description, time, organizer, max_people FROM events WHERE id=?",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            return crow::response(404, "Event not found");
        }

        std::string topic = (const char *)sqlite3_column_text(stmt, 0);
        std::string desc = (const char *)sqlite3_column_text(stmt, 1);
        std::string time = (const char *)sqlite3_column_text(stmt, 2);
        std::string org = (const char *)sqlite3_column_text(stmt, 3);
        int maxp = sqlite3_column_int(stmt, 4);
        sqlite3_finalize(stmt);

        int reg = count_registered(id);
        int spots = maxp - reg;

        // Check current user's registration status
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
           << "<strong>Organizer:</strong> " << html_escape(org)
           << " &mdash; <strong>Time:</strong> " << html_escape(time) << "</p>"
           << "<p>" << html_escape(desc) << "</p>"
           << "<p><strong>" << reg << "/" << maxp << "</strong> registered. ";
        if (spots > 0)
            os << badge(std::to_string(spots) + " spots left", "green");
        else
            os << badge("Full", "red");
        os << "</p>";

        if (my_status.empty()) {
            os << "<form method=\"POST\" action=\"/event/" << id << "/register\" class=\"inline-form\">"
               << "<button type=\"submit\" class=\"btn\">"
               << (spots > 0 ? "Register for this event" : "Join the waiting queue")
               << "</button></form>";
        } else if (my_status == "registered") {
            os << "<div class=\"status-box ok\">"
               << "You are registered for this event"
               << "<form method=\"POST\" action=\"/event/" << id << "/resign\" class=\"inline-form\">"
               << "<button type=\"submit\" class=\"btn btn-outline-danger btn-sm\">Resign</button></form>"
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
               << "You are #" << pos << " in the waiting queue"
               << "<form method=\"POST\" action=\"/event/" << id << "/resign\" class=\"inline-form\">"
               << "<button type=\"submit\" class=\"btn btn-outline-danger btn-sm\">Leave queue</button></form>"
               << "</div>";
        }

        os << "<h2>Registered (" << reg << "/" << maxp << ")</h2><ol>";
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
        if (!has_any_reg) os << "<p class=\"muted\">No one registered yet.</p>";

        sqlite3_prepare_v2(g_db,
                           "SELECT COUNT(*) FROM registrations WHERE event_id=? AND status='waitlisted'",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);
        sqlite3_step(stmt);
        int wcount = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);

        if (wcount > 0) {
            os << "<h2>Waiting Queue (" << wcount << ")</h2><ol>";
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

    // --- Register for event ---
    CROW_ROUTE(app, "/event/<int>/register").methods(crow::HTTPMethod::POST)([](const crow::request &req, int id) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db, "SELECT max_people FROM events WHERE id=?", -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            return crow::response(404);
        }
        int maxp = sqlite3_column_int(stmt, 0);
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

    // --- Resign from event ---
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
    // Admin routes
    // ============================================================

    // --- Admin dashboard ---
    CROW_ROUTE(app, "/admin")
    ([](const crow::request &req) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();
        if (u.role != "admin")
            return require_admin();

        std::ostringstream os;
        os << nav_html(u);
        os << "<h1>Admin &mdash; Events</h1>";

        os << "<h2>Create Event</h2>"
           << "<form method=\"POST\" action=\"/admin/event\">"
           << "<label>Topic</label>"
           << "<input name=\"topic\" placeholder=\"Event topic\" required>"
           << "<label>Description</label>"
           << "<textarea name=\"description\" placeholder=\"What is this event about?\" rows=\"3\" required></textarea>"
           << "<label>Date and Time</label>"
           << "<input name=\"time\" placeholder=\"2026-10-01 18:00\" required>"
           << "<label>Organizer</label>"
           << "<input name=\"organizer\" placeholder=\"Name\" required>"
           << "<label>Max Participants</label>"
           << "<input name=\"max_people\" type=\"number\" min=\"1\" placeholder=\"e.g. 30\" required>"
           << "<button type=\"submit\" class=\"btn\">Create Event</button>"
           << "</form><hr>";

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db, "SELECT id, topic, max_people FROM events ORDER BY id DESC", -1, &stmt, nullptr);

        bool any = false;
        os << "<h2>All Events</h2>";
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
               << "<p>" << reg << "/" << maxp << " registered";
            if (wcount > 0) os << ", " << wcount << " waiting";
            os << "</p>"
               << "<a class=\"btn btn-sm\" href=\"/admin/event/" << eid << "\">Manage</a>"
               << "</div>";
        }
        sqlite3_finalize(stmt);
        if (!any)
            os << "<p class=\"muted\">No events yet.</p>";

        os << foot;
        return crow::response(os.str());
    });

    // --- Create event ---
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
        std::string org = body.get("organizer") ? body.get("organizer") : "";
        int maxp = body.get("max_people") ? std::max(1, std::stoi(body.get("max_people"))) : 1;

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db,
                           "INSERT INTO events (topic, description, time, organizer, max_people) VALUES (?, ?, ?, ?, ?)",
                           -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, topic.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, desc.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, time.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, org.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 5, maxp);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return redirect("/admin");
    });

    // --- Admin event detail ---
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
                           "SELECT topic, description, time, organizer, max_people FROM events WHERE id=?",
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
        sqlite3_finalize(stmt);

        int reg = count_registered(id);

        std::ostringstream os;
        os << nav_html(u);
        os << "<h1>" << html_escape(topic) << "</h1>"
           << "<p class=\"meta\">"
           << "<strong>Organizer:</strong> " << html_escape(org)
           << " &mdash; <strong>Time:</strong> " << html_escape(time)
           << " &mdash; <strong>Max:</strong> " << maxp << "</p>"
           << "<p>" << html_escape(desc) << "</p>";

        // Registered table
        os << "<h2>Registered (" << reg << "/" << maxp << ")</h2>";
        sqlite3_prepare_v2(g_db,
                           "SELECT u.id, u.name, u.code FROM registrations r JOIN users u ON r.user_id=u.id "
                           "WHERE r.event_id=? AND r.status='registered' ORDER BY r.id",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);

        bool has_reg = false;
        os << "<table><tr><th>#</th><th>Name</th><th>ID</th><th>Action</th></tr>";
        int i = 1;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            has_reg = true;
            int uid = sqlite3_column_int(stmt, 0);
            os << "<tr><td>" << i++ << "</td>"
               << "<td>" << html_escape((const char *)sqlite3_column_text(stmt, 1)) << "</td>"
               << "<td>" << html_escape((const char *)sqlite3_column_text(stmt, 2)) << "</td>"
               << "<td><form method=\"POST\" action=\"/admin/event/" << id << "/remove\" style=\"margin:0\">"
               << "<input type=\"hidden\" name=\"user_id\" value=\"" << uid << "\">"
               << "<button type=\"submit\" class=\"btn btn-danger btn-sm\">Remove</button>"
               << "</form></td></tr>";
        }
        sqlite3_finalize(stmt);
        os << "</table>";
        if (!has_reg)
            os << "<p class=\"muted\">No one registered yet.</p>";

        // Waitlist table
        sqlite3_prepare_v2(g_db,
                           "SELECT u.id, u.name, u.code FROM registrations r JOIN users u ON r.user_id=u.id "
                           "WHERE r.event_id=? AND r.status='waitlisted' ORDER BY r.id",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, id);

        bool has_wait = false;
        std::ostringstream ws;
        ws << "<h2>Waiting Queue</h2><table><tr><th>#</th><th>Name</th><th>ID</th></tr>";
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

        os << "<h2>Edit Event</h2>"
           << "<form method=\"POST\" action=\"/admin/event/" << id << "/edit\">"
           << "<label>Topic</label>"
           << "<input name=\"topic\" value=\"" << html_escape(topic) << "\" required>"
           << "<label>Description</label>"
           << "<textarea name=\"description\" rows=\"3\" required>" << html_escape(desc) << "</textarea>"
           << "<label>Date and Time</label>"
           << "<input name=\"time\" value=\"" << html_escape(time) << "\" required>"
           << "<label>Organizer</label>"
           << "<input name=\"organizer\" value=\"" << html_escape(org) << "\" required>"
           << "<label>Max Participants</label>"
           << "<input name=\"max_people\" type=\"number\" min=\"1\" value=\"" << maxp << "\" required>"
           << "<button type=\"submit\" class=\"btn\">Update Event</button>"
           << "</form>"
           << "<hr>"
           << "<h2>Delete Event</h2>"
           << "<p>This will remove the event and all registrations.</p>"
           << "<form method=\"POST\" action=\"/admin/event/" << id << "/delete\">"
           << "<button type=\"submit\" class=\"btn btn-danger\">Delete Event</button>"
           << "</form>";

        os << foot;
        return crow::response(os.str());
    });

    // --- Edit event ---
    CROW_ROUTE(app, "/admin/event/<int>/edit").methods(crow::HTTPMethod::POST)([](const crow::request &req, int id) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();
        if (u.role != "admin")
            return require_admin();

        auto body = crow::query_string("?" + req.body);

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db,
                           "UPDATE events SET topic=?, description=?, time=?, organizer=?, max_people=? WHERE id=?",
                           -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, body.get("topic"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, body.get("description"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, body.get("time"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, body.get("organizer"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 5, std::max(1, std::stoi(body.get("max_people"))));
        sqlite3_bind_int(stmt, 6, id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        promote_waitlist(id);

        return redirect("/admin/event/" + std::to_string(id));
    });

    // --- Remove participant (admin) ---
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

    // --- Delete event ---
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
        os << "<h1>User Management</h1>";

        os << "<h2>Create User</h2>"
           << "<form method=\"POST\" action=\"/admin/users\">"
           << "<label>Full Name</label>"
           << "<input name=\"name\" placeholder=\"John Smith\" required>"
           << "<label>User ID</label>"
           << "<input name=\"code\" placeholder=\"e.g. 3A17\" required "
           << "pattern=\"[1-4][A-Ea-e]([1-9]|[12][0-9]|3[0-5])\" "
           << "title=\"Format: digit(1-4), letter(A-E), number(1-35)\" style=\"text-transform:uppercase\">"
           << "<label>Password</label>"
           << "<input name=\"password\" type=\"password\" placeholder=\"Min. 4 characters\" required minlength=\"4\">"
           << "<label>Role</label>"
           << "<select name=\"role\"><option value=\"user\">User</option><option value=\"admin\">Admin</option></select>"
           << "<button type=\"submit\" class=\"btn\">Create User</button>"
           << "</form><hr>";

        os << "<h2>All Users</h2>"
           << "<table><tr><th>ID</th><th>Name</th><th>Code</th><th>Role</th><th>Action</th></tr>";

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db, "SELECT id, name, code, role FROM users ORDER BY id", -1, &stmt, nullptr);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int uid = sqlite3_column_int(stmt, 0);
            os << "<tr><td>" << uid << "</td>"
               << "<td>" << html_escape((const char *)sqlite3_column_text(stmt, 1)) << "</td>"
               << "<td>" << html_escape((const char *)sqlite3_column_text(stmt, 2)) << "</td>"
               << "<td>" << badge((const char *)sqlite3_column_text(stmt, 3), std::string((const char *)sqlite3_column_text(stmt, 3)) == "admin" ? "yellow" : "green") << "</td>"
               << "<td>";
            if (uid != u.id) {
                os << "<form method=\"POST\" action=\"/admin/users/" << uid << "/delete\" style=\"margin:0\">"
                   << "<button type=\"submit\" class=\"btn btn-danger btn-sm\">Delete</button></form>";
            } else {
                os << "<span class=\"muted\">you</span>";
            }
            os << "</td></tr>";
        }
        sqlite3_finalize(stmt);
        os << "</table>";

        os << foot;
        return crow::response(os.str());
    });

    // --- Create user ---
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

    // --- Delete user ---
    CROW_ROUTE(app, "/admin/users/<int>/delete").methods(crow::HTTPMethod::POST)([](const crow::request &req, int uid) {
        std::lock_guard<std::mutex> lock(g_mutex);
        User u = get_current_user(req);
        if (!u.id)
            return require_login();
        if (u.role != "admin")
            return require_admin();
        if (uid == u.id)
            return redirect("/admin/users"); // can't delete yourself

        // Find events where this user is registered (not waitlisted) for promotion
        std::vector<int> events_to_promote;
        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(g_db,
                           "SELECT event_id FROM registrations WHERE user_id=? AND status='registered'",
                           -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, uid);
        while (sqlite3_step(stmt) == SQLITE_ROW)
            events_to_promote.push_back(sqlite3_column_int(stmt, 0));
        sqlite3_finalize(stmt);

        // Delete user (CASCADE deletes registrations)
        sqlite3_prepare_v2(g_db, "DELETE FROM users WHERE id=?", -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, uid);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        // Invalidate any sessions for this user
        for (auto it = g_sessions.begin(); it != g_sessions.end();) {
            if (it->second == uid)
                it = g_sessions.erase(it);
            else
                ++it;
        }

        // Promote waitlisted people for affected events
        for (int eid : events_to_promote)
            promote_waitlist(eid);

        return redirect("/admin/users");
    });

    app.port(8080).multithreaded().run();
}
