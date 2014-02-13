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
#include "http-request.h"

using namespace std;

#define SERVER_PORT "14886" // TODO: Change to 14886
#define MAX_CONNECTIONS 20  // Max number of connections allowed to the server
#define BUFFER_SIZE 1024    // Buffer size that we read in
#define TIMEOUT 30          // TODO: Change to 30 Timeout value for receiving requests from client

// Structure that is passed into the thread
typedef struct 
{
    int socket_fd; // File descriptor for the socket
}thread_data_t;

void* handle_connection(void* p)
{
    cout << "Handling connection\n";

    thread_data_t* args = (thread_data_t*) p;



    while(1) {
        
        string request_data;
        
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
                char buf[BUFFER_SIZE];
                read(args->socket_fd, buf, sizeof(buf));
                request_data.append(buf);
                memset(buf, 0, sizeof(buf));
            }else{
                string timeout = "Timeout Error\n";
                cout << timeout;
                write(args->socket_fd, timeout.c_str(), timeout.length());
                close(args->socket_fd);
                pthread_exit(NULL);
            }

        }

        cout << "Read in data: "<< request_data << endl;

        // Obtain the HTTP header from the request_data
        HttpRequest request;
        try
        {
            request.ParseRequest(request_data.c_str(), request_data.length());
        }catch (ParseException err)
        {
            cout << "Header parse exception: " << err.what() << endl;
            
            string error_exception = "404 Invalid Request\n";

            if (strcmp("Request is not GET", err.what()) == 0)
                error_exception = "501 Not Implemented\n";


            write(args->socket_fd, error_exception.c_str(), error_exception.length());
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
