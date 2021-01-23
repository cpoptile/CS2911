"""
- CS2911 - 041
- Fall 2020
- Lab 5
- Names:
  - Claudia Poptile
  - Parker Splitt

A simple HTTP client

Introduction: (Describe the lab in your own words)
This lab has some similarities from lab3 and lab4 such that we are trying to connect
to a client and write a response to the file. The goal of lab5 however, is to write
a request and save a web resource all while trying to act as an http client, which is
what differs it from the previous labs. An HTTP client can be used to send requests
and retrieve their responses.

Summary: (Summarize your experience with the lab and what you learned)
The main focus of this lab was creating HTTP requests to then send it to retrieve
the resource at the specified url. However a specification in this lab was to read
 both the content length as well as the chunked responses. At the end when
 everything was implemented correctly, what was written to a file was a green
 checkmark which in previous HTTP exercises was shown. What was printed to the
 console was the status code given by the server to confirm whether it was valid
 or not. Ideas from lab3 and 4 were taken into consideration when conducting this
 lab, however there were differences from tcp to HTTP clients.

Feedback: (Describe what you liked, what you disliked, and any suggestions
you have for improvement) (required)
One suggestion is to demo the lab from your code so when we do ours, we know what to look for
A rubric would also be nice

"""

# import the "socket" module -- not using "from socket import *" in order to
# selectively use items with "socket." prefix
import socket

# import the "regular expressions" module
import re


def main():
    """
    Tests the client on a variety of resources
    """

    # These resource request should result in "Content-Length" data transfer
    get_http_resource('http://www.httpvshttps.com/check.png', 'check.png')

    # this resource request should result in "chunked" data transfer
    get_http_resource('http://www.httpvshttps.com/','index.html')
    
    # If you find fun examples of chunked or Content-Length pages, please share
    # them with us!


def get_http_resource(url, file_name):
    """
    Get an HTTP resource from a server
           Parse the URL and call function to actually make the request.

    :param url: full URL of the resource to get
    :param file_name: name of file in which to store the retrieved resource

    (do not modify this function)
    """

    # Parse the URL into its component parts using a regular expression.
    url_match = re.search('http://([^/:]*)(:\d*)?(/.*)', url)
    match_groups = url_match.groups() if url_match else []
    #    print 'match_groups=',match_groups
    if len(match_groups) == 3:
        host_name = match_groups[0]
        host_port = int(match_groups[1][1:]) if match_groups[1] else 80
        host_resource = match_groups[2]
        print('host name = {0}, port = {1}, resource = {2}'
              .format(host_name, host_port, host_resource))
        status_string = do_http_exchange(host_name.encode(), host_port,
                                         host_resource.encode(), file_name)
        print('get_http_resource: URL="{0}", status="{1}"'
              .format(url, status_string))
    else:
        print('get_http_resource: URL parse failed, request not sent')


def do_http_exchange(host, port, resource, file_name):
    """
    Get an HTTP resource from a server

    :param bytes host: the ASCII domain name or IP address of the server machine
                       (i.e., host) to connect to
    :param int port: port number to connect to on server host
    :param bytes resource: the ASCII path/name of resource to get. This is
           everything in the URL after the domain name, including the first /.
    :param file_name: string (str) containing name of file in which to store the
           retrieved resource
    :return: the status code
    :rtype: int
    :author: Claudia Poptile + Parker Splitt
    """
    # establish data socket
    data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_socket.connect((host, port))
    # send HTTP request to retrieve resource at specified url
    request = b'GET ' + resource + b' HTTP/1.1\r\nHost: ' + host + b'\r\n\r\n'
    data_socket.sendall(request)
    # start reading info
    status_code = read_status_code(data_socket)
    encoding_type = get_encoding_type(data_socket)

    message = read_content(encoding_type, data_socket)

    write_file(file_name, message)
 
    return status_code


def read_status_code(data_socket):
    """
    Reads the first header in order to retrieve status line
    Then gets the status code from the status line
    :param data_socket: data socket to be read from
    :return: status code
    :rtype: int
    :author: Parker Splitt
    """
    header = b''
    while b'\r\n' not in header:
        header += next_byte(data_socket)
    index = header.index(b' ')
    status_code = header[index +1:index +4]
    return status_code.decode('ASCII')


def get_encoding_type(data_socket):
    """
    Reads the remaining HTTP headers in order to determine
    the HTTP transfer encoding type
    :param data_socket: data socket to be read from
    :return: transfer encoding type
    :rtype: bytes object
    :author: Claudia Poptile
    """
    encoding_type = b''
    header_name = b' '

    while header_name != b'':
        header_name = read_name(data_socket)
        if header_name == b'Content-Length' or header_name == b'Transfer-Encoding':
            encoding_type = get_value(data_socket)

    return encoding_type


def read_name(data_socket):
    """
    Retrieves name of HTTP header
    :param data_socket: data socket to be read from
    :return: HTTP header name
    :rtype: bytes object
    :author: Claudia Poptile
    """
    name = b''
    byte = b''

    while byte != b':':

        byte = next_byte(data_socket)

        if byte == b'\r':
            next_byte(data_socket)
            return name

        if byte != b':':
            name += byte

    return name


def get_value(data_socket):
    """
    Reads the value from an HTTP header
    :param data_socket: data socket to be read from
    :return: HTTP header value
    :rtype: bytes object
    :author: Parker Splitt
    """
    byte = b''
    values = byte
    next_byte(data_socket)

    while byte != b'\r':
        values += byte
        byte = next_byte(data_socket)
    return values


def read_content(encoding_type, data_socket):
    """
    Reads the content of the file determined by its encoding type
    :param encoding_type: reads the content inside of the header
    :param data_socket: the data socket
    :author: parker splitt
    """
    if encoding_type == b'chunked':
        message = read_chunks(data_socket)
    else:
        message = b''
        length = int(encoding_type.decode("ASCII"), 16)
        for i in range(0, length):
            message += next_byte(data_socket)
    return message


def read_chunks(data_socket):
    """
    Reads the chunks of the message if the data encoding type is chunked
    :param data_socket: the data socket
    :return: the message
    :rtype: bytes object
    :author: parker splitt
    """
    message = b''
    length = -1
    while length != 0:
        length_in_ascii = read_chunk_length(data_socket)
        if length != b'':
            length = int(length_in_ascii.decode("ASCII"), 16)
            message += read_chunk(data_socket, length)
            next_byte(data_socket)
            next_byte(data_socket)
    return message


def read_chunk_length(data_socket):
    """
    Gets the length of the chunk to be read
    :param data_socket: the data socket
    :return: length of chunk
    :rtype: bytes object
    :author: Claudia Poptile
    """
    length = b''
    byte = next_byte(data_socket)
    while byte != b'\r':
        length += byte
        byte = next_byte(data_socket)
    next_byte(data_socket)
    return length


def read_chunk(data_socket, length):
    """
    Reads a single chunk from the payload according to its length
    :param data_socket: the data socket
    :param length: number of bytes in chunk
    :return: data from single chunk
    :rtype: bytes object
    :author: parker splitt
    """
    message = b''
    for x in range(0, length):
        byte_read = next_byte(data_socket)
        message += byte_read
    return message


def write_file(file_name, message):
    """
    Writes HTTP web resource to specified file
    :param file_name: name of file
    :param message: message to be written
    :author: Claudia Poptile
    """
    file = open(file_name, 'wb')
    file.write(message)
    file.close()


def next_byte(data_socket):
    """
    Read the next byte from the socket data_socket.

    Read the next byte from the sender, received over the network.
    If the byte has not yet arrived, this method blocks (waits)
      until the byte arrives.
    If the sender is done sending and is waiting for your response, this method blocks indefinitely.

    :param data_socket: The socket to read from. The data_socket argument should be an open tcp
                        data connection (either a client socket or a server data socket), not a tcp
                        server's listening socket.
    :return: the next byte, as a bytes object with a single byte in it
    """
    return data_socket.recv(1)


main()
