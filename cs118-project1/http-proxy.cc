/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

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
using namespace std;

#define SERVER_PORT "14886" // TODO: Change to 14886
#define MAX_CONNECTIONS 20  // Max number of connections allowed to the server
#define BUFFER_SIZE 1024    // Buffer size that we read in

// Structure that is passed into the thread
typedef struct 
{
    int socket_fd; // File descriptor for the socket
}thread_data_t;

HttpResponse make_request(HttpRequest* request)
{
    int status;
    int s;
    struct addrinfo hints;
    struct addrinfo *servinfo;  // will point to the results
    memset(&hints, 0, sizeof hints); // make sure the struct is empty
    hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    int l= request->GetTotalLength();
    char *req_string=new char[l];
    request->FormatRequest(req_string);
    
    // get ready to connect
    char p[sizeof(short unsigned int)];
    short unsigned int temp= request->GetPort();
    memcpy ( p, &temp, sizeof(short unsigned int) );
    status = getaddrinfo(request->GetHost().c_str(), p, &hints, &servinfo);
    s = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    connect(s, servinfo->ai_addr, servinfo->ai_addrlen);
    send(s, req_string, l, 0);
    
    string response_data;
    while (memmem(response_data.c_str(), response_data.length(), "\r\n\r\n", 4) == NULL)
    {
        char buf[BUFFER_SIZE];
        read(s, buf, sizeof(buf));
        response_data.append(buf);
        memset(buf, 0, sizeof(buf));
    }
    
    HttpResponse resp;
    resp.ParseResponse(response_data.c_str(), response_data.length());
    return resp;

    
    
}

void* handle_connection(void* p)
{
    cout << "Handling connection\n";

    thread_data_t* args = (thread_data_t*) p;
    string request_data;

    // Read in data until there are two new lines in the buffer
    while (memmem(request_data.c_str(), request_data.length(), "\r\n\r\n", 4) == NULL)
    {
        char buf[BUFFER_SIZE];
        read(args->socket_fd, buf, sizeof(buf));
        request_data.append(buf);
        memset(buf, 0, sizeof(buf));
    }

    cout << "Read in data: "<< request_data << endl;

    // Obtain the HTTP header from the request_data
    HttpHeaders header;
    try
    {
        header.ParseHeaders(request_data.c_str(), request_data.length());
    }catch (ParseException err)
    {
        cout << "Header parse exception: " << err.what() << endl;
        
        string s = "404 Invalid Request\n";
        write(args->socket_fd, s.c_str(), s.length());
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

            pthread_create(&thread, NULL, handle_connection, (void*) p);
            pthread_detach(thread);
        }

    }


    return 0;
}
