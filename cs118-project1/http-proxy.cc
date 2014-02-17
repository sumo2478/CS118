#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>

#include "compat.h"

#include "http-headers.h"
#include "http-response.h"
#include "http-request.h"

#include <sstream>
#include <map>
using namespace std;

#define SERVER_PORT "14886" // TODO: Change to 14886
#define MAX_CONNECTIONS 20  // Max number of connections allowed to the server
#define BUFFER_SIZE 1024    // Buffer size that we read in
#define TIMEOUT 1          // TODO: Change to 30 Timeout value for receiving requests from client
#define REMOTE_TIMEOUT 10
class Cache;
// Structure that is passed into the thread
typedef struct 
{
    int socket_fd; // File descriptor for the socket
    Cache* cache_p;
}thread_data_t;

pthread_mutex_t cache_mutex;
// Need:
// pthread_mutex_init(&cache_mutex, NULL);
// pthread_mutex_lock(&cache_mutex);
// pthread_mutex_unlock(&cache_mutex);

class Cache
{
public:
    bool CacheEntryExists(HttpRequest * hr);
    void store(HttpRequest* hr, string savedResponse);
    void remove(HttpRequest* hr);
    string EntryLastModified(HttpRequest * hr);
    string EntryExpires(HttpRequest * hr);
    string ReturnStoredResponse(HttpRequest * hr);
    int size() {
        return cacheMap.size();
    }
private:
    map<string,string> cacheMap;
};

// Returns true if proxy has visited the server before
bool Cache::CacheEntryExists(HttpRequest * hr) {
    string hostName = hr->GetHost();
    string pathName = hr->GetPath();
    string keyName = hostName + pathName;
    map<string,string>::iterator it;
    it = cacheMap.find(keyName);
    if(it == cacheMap.end())
        return false;
    else
        return true;
}

// Updates the map with the new HTTP response under the key
void Cache::store(HttpRequest * hr, string savedResponse) {
    string hostName = hr->GetHost();
    string pathName = hr->GetPath();
    string keyName = hostName + pathName;
    cacheMap.erase(keyName);
    cacheMap.insert(pair<string,string>(keyName, savedResponse));
}

// Deletes the saved cache data (FOR USE LATER IN Expired cache)
// Expiration date needs to be implemented
void Cache::remove(HttpRequest * hr) {
    string hostName = hr->GetHost();
    string pathName = hr->GetPath();
    string keyName = hostName + pathName;
    cacheMap.erase(keyName);
}

// Returns the string of the last-modified header tag
// in the saved HTTP response
string Cache::EntryLastModified(HttpRequest * hr) {
    string hostName = hr->GetHost();
    string pathName = hr->GetPath();
    string keyName = hostName + pathName;
    map<string,string>::iterator it;
    it = cacheMap.find(keyName);
    if(it != cacheMap.end()) {
        string raw = (*it).second;
        HttpResponse response;
        response.ParseResponse(raw.c_str(), raw.length());
        string last_modified = response.FindHeader("Last-Modified");
        return last_modified;
    }
    else
        return "";
}

string Cache::EntryExpires(HttpRequest * hr) {
    string hostName = hr->GetHost();
    string pathName = hr->GetPath();
    string keyName = hostName + pathName;
    map<string,string>::iterator it;
    it = cacheMap.find(keyName);
    if(it != cacheMap.end()) {
        string raw = (*it).second;
        HttpResponse response;
        response.ParseResponse(raw.c_str(), raw.length());
        string Expires = response.FindHeader("Expires");
        return Expires;
    }
    else
        return "";
}

// Returns the string of the HTTP response
string Cache::ReturnStoredResponse(HttpRequest * hr) {
    string hostName = hr->GetHost();
    string pathName = hr->GetPath();
    string keyName = hostName + pathName;
    map<string,string>::iterator it;
    it = cacheMap.find(keyName);
    if(it != cacheMap.end()) {
        return (*it).second;
    }
    else
        return "";
}




string make_request(HttpRequest* request, Cache* cache)
{
    int status;
    int s;
    struct addrinfo hints;
    struct addrinfo *servinfo;       // will point to the results
    bool requestCached= false;
    
    memset(&hints, 0, sizeof hints); // make sure the struct is empty
    hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    
    requestCached= cache->CacheEntryExists(request); //check if response for the request has been cached b4
    
    if(requestCached)
    {
        request->AddHeader("If-Modified-Since", cache->EntryLastModified(request));
    }
    
    size_t l = request->GetTotalLength();

    char* req_string = new char[l];

    request->FormatRequest(req_string);

    cout << "Received request: " << req_string;

    // Obtain port number
    stringstream ss;
    ss << request->GetPort();
    string port_num = ss.str();

    status = getaddrinfo(request->GetHost().c_str(), port_num.c_str(), &hints, &servinfo);

    s = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    connect(s, servinfo->ai_addr, servinfo->ai_addrlen);
    send(s, req_string, l, 0);
    string response_data;


    // Retrieve the HTTP header
    while (memmem(response_data.c_str(), response_data.length(), "\r\n\r\n", 4) == NULL)
    {
        
        struct timeval timeout; // Timeout value
        timeout.tv_sec = REMOTE_TIMEOUT;
        timeout.tv_usec = 0;

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(s, &read_fds);

        // Wait until there is data inside the read pipe
        // If the timer timesout then close connection
        if (select(s+1, &read_fds, NULL, NULL, &timeout))
        {        
            char buf[BUFFER_SIZE];
            memset(buf, 0, sizeof(buf));
            int i = recv(s, buf, sizeof(buf), 0);
            response_data.append(buf, i);        
    
        }else{
            cout << "Timeout" << endl;
            break;
        }

    }

   

    HttpResponse response;
    response.ParseResponse(response_data.c_str(), response_data.length());
    cout<<"THE RESPONSE STATUS CODE IS"<<response.GetStatusCode()<<"!!!!";
    bool cacheIt= false;//decide whether response needs to be cached
    
    cacheIt= !(response.GetStatusCode()=="304");//only scenario we do not cache is if Not Modified is the Status Message
    
    // If there was any body code that was placed in the buffer add it to current body
    string body = response_data.substr(response_data.find("\r\n\r\n"));
    
    // Determine the content length
    stringstream ss_body(response.FindHeader("Content-Length"));
    int content_length;
    ss_body >> content_length;

    content_length -= body.length();
    content_length += 4;

    // Retrieve the rest of the body
    while (content_length > 0)
    {
        struct timeval timeout; // Timeout value
        timeout.tv_sec = REMOTE_TIMEOUT;
        timeout.tv_usec = 0;

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(s, &read_fds);

        // Wait until there is data inside the read pipe
        // If the timer timesout then close connection
        if (select(s+1, &read_fds, NULL, NULL, &timeout))
        {        
            char buf[BUFFER_SIZE];
            memset(buf, 0, sizeof(buf));
            int i = recv(s, buf, content_length, 0);
            body.append(buf, i);    
            content_length -= i;    
    
        }else{
            cout << "Timeout" << endl;
            break;
        }
    }

    close(s);
    delete[] req_string;

    if(!cacheIt || (requestCached))
    {
        
        cout<<"returns cached response";
        cout<<"---------------------------------------------\n";
        cout<< cache->ReturnStoredResponse(request);
        cout<<"-------------------------------------------";
        return cache->ReturnStoredResponse(request);//simply return stored response from the cache
        
    }

    // Append the body to the header
    response_data = response_data.substr(0, response_data.find("\r\n\r\n"));
    response_data.append(body);
    
    if (response.FindHeader("Last-Modified")!="")
    {
        cout<<"storing response";
        cache->store(request, response_data);
        
    }
    cout<<"---------------------------------------------\n";
        cout<< response_data;
        cout<<"-------------------------------------------";
    return response_data;
    
    
}

void* handle_connection(void* p)
{
    cout << "Handling connection" << endl;

    thread_data_t* args = (thread_data_t*) p;

    bool persist = true;

    while(1) {

        cout << "Serving Request" << endl;
        string request_data;
        char buf[BUFFER_SIZE];

        // Read in data until there are two new lines in the buffer
        while (memmem(request_data.c_str(), request_data.length(), "\r\n\r\n", 4) == NULL)
        {
            
            struct timeval timeout; // Timeout value
            timeout.tv_sec = TIMEOUT;
            timeout.tv_usec = 0;

            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(args->socket_fd, &read_fds);

            // Wait until there is data inside the read pipe
            // If the timer timesout then close connection
            if (select(args->socket_fd+1, &read_fds, NULL, NULL, &timeout))
            {        
                int i = recv(args->socket_fd, buf, sizeof(buf), 0);

                if(strcmp(buf, "") == 0)
                {
                    cout << "Exiting\n";
                    close(args->socket_fd);
                    pthread_exit(NULL);
                }

                request_data.append(buf, i);
                memset(buf, 0, sizeof(buf));
        
            }else{
                string timeout = "Timeout Error\n";
                cout << timeout;
                write(args->socket_fd, timeout.c_str(), timeout.length());
                close(args->socket_fd);
                pthread_exit(NULL);
            }
            
        }

        // Obtain the HTTP header from the request_data
        HttpRequest request;
        try
        {
            request.ParseRequest(request_data.c_str(), request_data.length());
            
            if (strcmp(request.FindHeader("Connection").c_str(), "close") == 0)
            {
                persist = false;
            }
            string response_str = make_request(&request,args->cache_p);
        
            // cout << "Responding with: " << response_str;
            send(args->socket_fd, response_str.c_str(), response_str.length(), 0);            
        }catch (ParseException err)
        {
            cout << "Header parse exception: " << err.what() << endl;
            
            string error_exception = "404 Invalid Request\n";

            if (strcmp("Request is not GET", err.what()) == 0)
                error_exception = "501 Not Implemented\n";


            write(args->socket_fd, error_exception.c_str(), error_exception.length());
            break;
        }

        if (!persist)
        {
            cout << "Connection closing...\n";
            break;            
        }
    }

    cout << "Exiting" << endl;

    // Close the socket and exit the thread
    close(args->socket_fd);
    pthread_exit(NULL);
}

int create_server_listener (const char* port_num)
{
    struct addrinfo hints;
    struct addrinfo* res;

    memset(&hints, 0, sizeof(hints));  // Make sure struct is empty

    // Set hints structure
    hints.ai_family = AF_INET;         // Allows IPv4
    hints.ai_socktype = SOCK_STREAM;   // TCP stream sockets
    hints.ai_flags = AI_PASSIVE;       // Automatic fill in for IP

    if (getaddrinfo(NULL, port_num, &hints, &res) != 0)
    {
        fprintf(stderr, "Get address info error\n");
        return -1;
    }

    // Initialize the socket
    int listen_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if (listen_socket < 0)
    {
        fprintf(stderr, "Unable to create server socket\n");
        return -1;
    }

    // Bind the socket
    int status = bind(listen_socket, res->ai_addr, res->ai_addrlen);

    if (status < 0)
    {
        fprintf(stderr, "Failed to bind socket\n");
        return -1;
    }

    // Setup the listener
    if (listen(listen_socket, MAX_CONNECTIONS))
    {
        fprintf(stderr, "Failed to set up listener\n");
        return -1;
    }

    // Free the used memory
    freeaddrinfo(res);

    return listen_socket;
}

int main (int argc, char *argv[])
{
    // Open a socket for listening
    int listen_socket = create_server_listener(SERVER_PORT);

    if (listen_socket < 0)
        return -1;

    cout << "Server listening on port " << SERVER_PORT << endl;
    Cache* cache= new Cache;
    while(1)
    {

        struct sockaddr_storage connection_addr;
        socklen_t addr_size = sizeof(connection_addr);

        int new_connection = accept(listen_socket, (struct sockaddr *) &connection_addr, &addr_size);

        cout << "Connected to: " << new_connection << endl;
        
        if (new_connection < 0)
        {
            cout << "Connection failed...\n";
            continue;
        }else
        {
            pthread_t thread;
            thread_data_t* p = new thread_data_t;
            p->socket_fd = new_connection;
            p->cache_p= cache;
            pthread_create(&thread, NULL, handle_connection, (void*) p);
            pthread_detach(thread);
        }

    }


    return 0;
}
