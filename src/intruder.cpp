#include "intruder.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp> // For directory creation
#include "DataTypes.hpp"       // For ParsedHttpData
#include "EncodingUtils.hpp"// For directory creation

// Use namespaces for cleaner code
using boost::asio::ip::tcp;
using namespace std;

// Helper function to read a file's content into a string
string read_file_content(const string& path) {
    ifstream file(path);
    if (!file) {
        throw runtime_error("Could not open file: " + path);
    }
    return string((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

// Helper function to read a file's lines into a vector of strings
vector<string> read_file_lines(const string& path) {
    vector<string> lines;
    ifstream file(path);
    if (!file) {
        throw runtime_error("Could not open file: " + path);
    }
    string line;
    while (getline(file, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(line);
    }
    return lines;
}

// Helper function to extract the Host header from a raw HTTP request
string get_host_from_template(const string& request_template) {
    istringstream stream(request_template);
    string line;
    while (getline(stream, line)) {
        if (line.substr(0, 5) == "Host:") {
            // Found the host line
            string host = line.substr(6); // Skip "Host: "
            // Trim leading/trailing whitespace
            host.erase(0, host.find_first_not_of(" \t\r"));
            host.erase(host.find_last_not_of(" \t\r") + 1);
            return host;
        }
    }
    return ""; // Not found
}

// The main function for the Intruder feature
void run_intruder() {
    try {
        // 1. Get user input
        string template_path, payload_path, output_dir;
        cout << "--- Intruder Mode ---\n";
        cout << "Enter path to request template file: ";
        cin >> template_path;
        cout << "Enter path to payload file: ";
        cin >> payload_path;
        cout << "Enter path to output directory: ";
        cin >> output_dir;

        // Create the output directory if it doesn't exist
        boost::filesystem::create_directories(output_dir);

        // 2. Read files
        string request_template = read_file_content(template_path);
        vector<string> payloads = read_file_lines(payload_path);

        // 3. Find injection marker and target host
        size_t injection_pos = request_template.find("§");
        if (injection_pos == string::npos) {
            cerr << "Error: Injection marker '§' not found in the template file.\n";
            return;
        }

        string host_and_port = get_host_from_template(request_template);
        if (host_and_port.empty()) {
            cerr << "Error: 'Host:' header not found in the template file.\n";
            return;
        }
        
        // Fix for Host/Port Parsing
        string host;
        string port = "80"; // Default to port 80 for HTTP
        
        size_t port_colon_pos = host_and_port.find(":");
        if (port_colon_pos != string::npos) {
            host = host_and_port.substr(0, port_colon_pos);
            port = host_and_port.substr(port_colon_pos + 1);
        } else {
            host = host_and_port;
        }
        cout << "Target host identified: " << host<< "\n";
        // 4. Loop through payloads and send requests
        int request_count = 0;
        
        for (const auto& payload : payloads) {
            // try karte hai andar daalne pe kya fark aata hai
            boost::asio::io_context io_context;
            request_count++;
            cout << "Sending request " << request_count << "/" << payloads.size() << " with payload: \"" << payload << "\"\n";

            // Create the final request by injecting the payload
            string final_request = request_template;
            // The § character is 2 bytes long in UTF-8. We must replace both bytes.
            final_request.replace(injection_pos, 2, payload);
            
            // cout<<"Initial request is:"<<endl;
            // cout<<request_template<<endl;
            // cout<<"---------------------------------------\n";
            
            // Normalize line endings to ensure HTTP compliance (\r\n)
            size_t body_pos = final_request.find("\n\n");
            if (body_pos != string::npos) {
                string headers_part = final_request.substr(0, body_pos);
                string body_part = final_request.substr(body_pos + 2);
                
                // Replace all standalone \n with \r\n in the headers part
                string new_headers;
                for (size_t i = 0; i < headers_part.length(); ++i) {
                    if (headers_part[i] == '\n' && (i == 0 || headers_part[i-1] != '\r')) {
                        new_headers += "\r\n";
                    } else {
                        new_headers += headers_part[i];
                    }
                }
                final_request = new_headers + "\r\n\r\n" + body_part;
            }
    
            cout<<"Final request is:"<<endl;
            cout<<final_request<<endl;
            cout<<"---------------------------------------\n";
            // Automatically update Content-Length for POST requests
            size_t body_start_pos = final_request.find("\r\n\r\n");
            if (body_start_pos != string::npos) {
                string body = final_request.substr(body_start_pos + 4);
                size_t cl_header_pos = final_request.find("Content-Length:");
                if (cl_header_pos != string::npos) {
                    size_t cl_line_end = final_request.find("\r\n", cl_header_pos);
                    string new_cl_line = "Content-Length: " + to_string(body.length());
                    final_request.replace(cl_header_pos, cl_line_end - cl_header_pos, new_cl_line);
                }
            }

            // Set up the connection
            tcp::resolver resolver(io_context);
            tcp::socket socket(io_context);
            boost::asio::connect(socket, resolver.resolve(host, port));

            // Send the request
            boost::asio::write(socket, boost::asio::buffer(final_request));

            // Read the response
            boost::asio::streambuf response_buf;
            boost::system::error_code ec;
            boost::asio::read(socket, response_buf, ec);

            // Save the response to a file
            string output_filename = output_dir + "/response_" + to_string(request_count) + ".txt";
            ofstream out_file(output_filename);
            if (response_buf.size() > 0) {
                out_file << &response_buf;
            } else {
                out_file << "[No response or connection error]";
            }
            out_file.close();
        }

        cout << "\nIntruder run finished. " << request_count << " responses saved to " << output_dir << "\n";

    } catch (const exception& e) {
        cerr << "An error occurred: " << e.what() << '\n';
    }
}