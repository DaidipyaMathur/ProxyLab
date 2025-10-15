#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

using namespace std;
using namespace boost::asio;

struct HttpRequest {
    string method = "GET", path = "/", version = "1.1";
    string host = "example.com", port = "80", body;
    map<string, string> headers;

    HttpRequest() {
        headers["User-Agent"] = "Proxylab-Repeater/1.0";
        headers["Accept"] = "*/*";
        headers["Connection"] = "close";
    }

    void update_content_length() {
        if (!body.empty())
            headers["Content-Length"] = std::to_string(body.size());
        else
            headers.erase("Content-Length");
    }

    string to_string() const {
        stringstream ss;
        ss << method << " " << path << " HTTP/" << version << "\r\n";
        ss << "Host: " << host << "\r\n";
        for (auto &h : headers)
            ss << h.first << ": " << h.second << "\r\n";
        ss << "\r\n" << body;
        return ss.str();
    }
};

struct History {
    int id;
    string request, response;
};

vector<History> history;
int req_id = 1;

string send_request(const HttpRequest &req) {
    string result = "Error: could not send request.";
    try {
        io_context io;
        ssl::context ctx(ssl::context::tlsv12_client);
        ctx.set_default_verify_paths();

        ip::tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(req.host, req.port);

        if (req.port == "443") {
            ssl::stream<ip::tcp::socket> sock(io, ctx);
            connect(sock.lowest_layer(), endpoints);
            sock.handshake(ssl::stream_base::client);
            write(sock, buffer(req.to_string()));

            boost::asio::streambuf buf;
            boost::system::error_code ec;
            read(sock, buf, ec);
            stringstream ss; ss << &buf;
            result = ss.str();
        } else {
            ip::tcp::socket sock(io);
            connect(sock, endpoints);
            write(sock, buffer(req.to_string()));

            boost::asio::streambuf buf;
            boost::system::error_code ec;
            read(sock, buf, ec);
            stringstream ss; ss << &buf;
            result = ss.str();
        }
    } catch (exception &e) {
        result = string("Exception: ") + e.what();
    }
    return result;
}

void show_menu() {
    cout << "\nProxylab Repeater\n"
         << "1. Set Target (Host/Port)\n"
         << "2. Edit Request Line\n"
         << "3. Edit Headers\n"
         << "4. Edit Body\n"
         << "5. Send Request\n"
         << "6. View History\n"
         << "7. Exit\n> ";
}

int main() {
    HttpRequest req;
    while (true) {
        show_menu();
        string line; getline(cin, line);
        int choice = -1;
        try { choice = stoi(line); } catch (...) {}

        if (choice == 1) {
            cout << "Host: "; getline(cin, req.host);
            cout << "Port (80 or 443): "; getline(cin, req.port);
        } 
        else if (choice == 2) {
            cout << "Method: "; getline(cin, req.method);
            cout << "Path: "; getline(cin, req.path);
        } 
        else if (choice == 3) {
            cout << "Header Name (blank to stop):\n";
            while (true) {
                string k, v;
                cout << "Key: "; getline(cin, k);
                if (k.empty()) break;
                cout << "Value: "; getline(cin, v);
                req.headers[k] = v;
            }
        } 
        else if (choice == 4) {
            cout << "Enter body (end with a line 'EOF'):\n";
            req.body.clear();
            while (getline(cin, line) && line != "EOF")
                req.body += line + "\n";
            if (!req.body.empty()) req.body.pop_back();
            req.update_content_length();
        } 
        else if (choice == 5) {
            cout << "\nSending request to " << req.host << "...\n";
            string resp = send_request(req);
            cout << "\n--- RESPONSE START ---\n" << resp << "\n--- RESPONSE END ---\n";
            history.push_back({req_id++, req.to_string(), resp});
        } 
        else if (choice == 6) {
            if (history.empty()) cout << "No history.\n";
            for (auto &h : history) {
                cout << "\n#Request " << h.id << "\n"
                     << "----- REQUEST -----\n" << h.request
                     << "\n----- RESPONSE -----\n" << h.response.substr(0, 500)
                     << "\n--------------------\n";
            }
        } 
        else if (choice == 7) break;
        else cout << "Invalid option.\n";
    }
    return 0;
}
