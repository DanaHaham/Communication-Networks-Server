// Name: Dana Haham
// ID: 209278407

// Name: Yarin Baslo
// ID: 209344589

#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <fstream>
#include <winsock2.h>
#include <string.h>
#include <time.h>
#include <queue>
#include <sstream>
#include <filesystem>
#include <chrono>
#include <unordered_map>

#pragma comment(lib, "Ws2_32.lib")
using namespace std;


// Consts
const int PORT = 8080;

const int MAX_SOCKETS = 60;
const int MAX_MSG = 50;
const int MAX_DATA = 1024;

enum SocketStates { EMPTY, LISTEN, RECEIVE, IDLE, SEND };

const string StrMethods[7] = { "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE" };
enum Methods { OPTIONS, GET, HEAD, POST, PUT, DELETE_, TRACE };

const string StrStatusCode[6] = { "200 OK", "201 Created", "204 No Content", "404 Not Found", "500 Internal Server Error", "405 Method Not Allowed"};
enum StatusCode { OK, CREATED, NO_CONTENT, NOT_FOUND, SERVER_ERROR, NOT_ALLOWED};

const string StrContentType[3] = {"text/html", "text/plain", "message/http"};
enum ContentType {HTML, PLAIN, MESSAGE};

const unordered_map<string, vector<Methods>> routes =
{
	{"/index.html",{OPTIONS, GET, HEAD, POST, TRACE}},
	{"/about.html",{OPTIONS, GET, HEAD, POST, TRACE}},
	{"/contact.html",{OPTIONS, GET, HEAD, POST, TRACE}},
	{"/developers.txt",{OPTIONS, POST, PUT, DELETE_, TRACE}},
	{"/*", {OPTIONS}},
	{"/", {OPTIONS, POST, TRACE}},
};

enum Validtion {VALID, ROUTE_NOT_ALLOWED, ROUTE_NOT_FOUND};

const string PathPages = "\\pages\\";


// Structs
struct Request
{
	string method;
	string uri;
	string path;
	string langQuery;
	string content;
};

struct SocketState
{
	SOCKET id;			// Socket handle
	int	recv;			// Receiving?
	int	send;			// Sending?
	queue<Request> buffer; // All the request in a buffer
	chrono::time_point<std::chrono::steady_clock> lastActivityTime; // Last activity
};


// Functions
void InitWinsock();
SOCKET CreateSocket();
sockaddr_in ConnectNetwork();
void BindSocket(SOCKET m_socket, sockaddr_in serverService);
void ListenSocket(SOCKET m_socket, sockaddr_in serverService);

void UpdateWaits(SocketState* sockets, int* socketsCount, fd_set* waitRecv, fd_set* waitSend);
int SelectRequest(fd_set* waitRecv, fd_set* waitSend);

bool AddSocket(SocketState* sockets, int* socketsCount, SOCKET id, int what);
void RemoveSocket(SocketState* sockets, int* socketsCount, int index);
void AcceptConnection(SocketState* sockets, int* socketsCount, int index);
void ReceiveMsg(SocketState* sockets, int* socketsCount, int index);
void SendMsg(SocketState* sockets, int index);

void HandleConnections(SocketState* sockets, int socketsCount);
Request HandelRequest(char* message);
string AnswerRequest(Request request);

string GetHead(Request request);
string Options(Request request);
string Delete(Request request);
string Put(Request request);
string Post(Request request);
string Trace(Request request);
string NotAllowed(Request request);
string NotFound(Request request);

string AllowMethodsStr(Request request);
Validtion IsValidRequest(Request request);
bool isInactive(SocketState socket);
string GetHeader(StatusCode code, ContentType type, int contentSize, string extra);
string GetDate();
void CloseProgram(char* message, bool isWSAActive, bool isSocketActive, SOCKET m_socket);

void main()
{
	// Create sockets Array for non-blocking server
	struct SocketState sockets[MAX_SOCKETS] = { EMPTY };
	int socketsCount = 0;

	// Initialize Windows Sockets
	InitWinsock();
	
	// Create a SOCKET object that listen through the socket for incoming connections
	SOCKET listenSocket = CreateSocket();

	// Create a sockaddr_in object called serverService 
	sockaddr_in serverService = ConnectNetwork();

	// Bind the socket for client's requests
	BindSocket(listenSocket, serverService);

	// Listen on the Socket for incoming connections
	ListenSocket(listenSocket, serverService);

	// Add the listener socket to the array
	AddSocket(sockets, &socketsCount, listenSocket, LISTEN);

	// Accept connections and handles them one by one
	HandleConnections(sockets, socketsCount);

	// Create error message
	char message[MAX_MSG];
	sprintf(message, "Server: Closing Connection.\n");

	// Close program
	CloseProgram(message, true, true, listenSocket);
}

// Initialize Winsock (Windows Sockets)
// Close the program in case it fails 
void InitWinsock()
{
	WSAData wsaData;

	// In case of error
	if (NO_ERROR != WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		// Create error message
		char message[MAX_MSG] = "Server: Error at WSAStartup()";

		// Close program
		CloseProgram(message, false, false, INVALID_SOCKET);
	}
}

// Create a socket to an internet address
// After initialization, a SOCKET object is ready to be instantiated.
// Close the program in case it fails 
SOCKET CreateSocket()
{
	SOCKET connSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// In case of error
	if (INVALID_SOCKET == connSocket)
	{
		// Create error message
		char message[MAX_MSG];
		sprintf(message, "Server: Error at socket(): %d", WSAGetLastError());

		// Close program
		CloseProgram(message, true, false, INVALID_SOCKET);
	}

	return connSocket;
}

// Create and initialize sockaddr_in object
// Assemble the required data for connection in sockaddr structure
sockaddr_in ConnectNetwork()
{
	// Create sockaddr_in object
	sockaddr_in serverService;

	// Assemble the required data for connection in sockaddr structure
	serverService.sin_family = AF_INET;
	serverService.sin_addr.s_addr = INADDR_ANY;	//inet_addr("127.0.0.1");
	serverService.sin_port = htons(PORT);

	return serverService;
}

// Establishes a connection to the given socket
void BindSocket(SOCKET m_socket, sockaddr_in serverService)
{
	// In case of error
	if (SOCKET_ERROR == bind(m_socket, (SOCKADDR*)&serverService, sizeof(serverService)))
	{
		// Create error message
		char message[MAX_MSG];
		sprintf(message, "Server: Error at bind(): %d", WSAGetLastError());

		// Close program
		CloseProgram(message, true, true, m_socket);
	}
}

// Listen on the given Socket for incoming connections
void ListenSocket(SOCKET m_socket, sockaddr_in serverService)
{
	// In case of error
	if (SOCKET_ERROR == listen(m_socket, 5))
	{
		// Create error message
		char message[MAX_MSG];
		sprintf(message, "Server: Error at socket(): %d", WSAGetLastError());

		// Close program
		CloseProgram(message, true, true, m_socket);
	}
}

// Check what to do next according to the given waits and returns the number of descriptors which are ready for use
int SelectRequest(fd_set* waitRecv, fd_set* waitSend)
{
	int nfd;

	// Determines the status of one or more sockets, waiting if necessary, to perform asynchronous I/O
	nfd = select(0, waitRecv, waitSend, NULL, NULL);

	// In case of error
	if (nfd == SOCKET_ERROR)
	{
		// Create error message
		char message[MAX_MSG];
		sprintf(message, "Server: Error at select(): %d", WSAGetLastError());

		// Close program
		CloseProgram(message, true, false, INVALID_SOCKET);
	}

	return nfd;
}

// Accept connections and handles them one by one
void HandleConnections(SocketState* sockets, int socketsCount)
{
	while (true)
	{
		// Wait for interesting event 
		fd_set waitRecv, waitSend;
		UpdateWaits(sockets, &socketsCount, &waitRecv, &waitSend);

		int nfd = SelectRequest(&waitRecv, &waitSend);

		// Run the wanted action according to the waitRecv, waitSend
		for (int i = 0; i < MAX_SOCKETS && nfd > 0; i++)
		{
			// There are receive requests
			if (FD_ISSET(sockets[i].id, &waitRecv))
			{
				nfd--;
				switch (sockets[i].recv)
				{
				case LISTEN:
					AcceptConnection(sockets, &socketsCount,i);
					break;

				case RECEIVE:
					ReceiveMsg(sockets, &socketsCount, i);
					break;
				}
			}

			// There are send requests
			if (FD_ISSET(sockets[i].id, &waitSend))
			{
				nfd--;
				switch (sockets[i].send)
				{
				case SEND:
					SendMsg(sockets, i);
					break;
				}
			}
		}
	}
}

// Update the given waitRecv and waitSend according to the given sockets array
void UpdateWaits(SocketState* sockets, int* socketsCount, fd_set* waitRecv, fd_set* waitSend)
{
	// Search for receive  and send requests
	FD_ZERO(waitRecv);
	FD_ZERO(waitSend);

	for (int i = 0; i < MAX_SOCKETS; i++)
	{
		// Socket is inactive
		if (sockets[i].recv == RECEIVE && sockets[i].send == IDLE && isInactive(sockets[i]))
		{
			closesocket(sockets[i].id);
			RemoveSocket(sockets, socketsCount, i);
		}

		// Add the socket to the waitRecv
		else if ((sockets[i].recv == LISTEN) || (sockets[i].recv == RECEIVE))
		{
			FD_SET(sockets[i].id, waitRecv);
		}
			

		// Add the socket to the waitSend
		if (sockets[i].send == SEND)
		{
			FD_SET(sockets[i].id, waitSend);
		}
	}
}

// Add the given socket to the given sockets array
bool AddSocket(SocketState* sockets, int* socketsCount, SOCKET id, int what)
{
	// Set the socket to be in non-blocking mode.
	unsigned long flag = 1;
	if (ioctlsocket(id, FIONBIO, &flag) != 0)
	{
		cout << "Server: Error at ioctlsocket(): " << WSAGetLastError() << endl;
	}

	// Search for an empty cell in the given sockets array 
	for (int i = 0; i < MAX_SOCKETS; i++)
	{
		if (sockets[i].recv == EMPTY)
		{
			sockets[i].id = id;
			sockets[i].recv = what;
			sockets[i].send = IDLE;
			sockets[i].lastActivityTime = chrono::steady_clock::now();
			*socketsCount = *socketsCount + 1;
			return true;
		}
	}

	return false;
}

// Remove the given socket from the given sockets array
void RemoveSocket(SocketState* sockets, int* socketsCount, int index)
{
	sockets[index].recv = EMPTY;
	sockets[index].send = EMPTY;
	sockets[index].buffer = queue<Request>();
	*socketsCount = *socketsCount - 1;
}

// Accept the connection to the given socket and add the new socket to the given array
void AcceptConnection(SocketState* sockets, int* socketsCount, int index)
{
	SOCKET id = sockets[index].id;
	struct sockaddr_in from;		// Address of sending partner
	int fromLen = sizeof(from);

	// Accept the new socket
	SOCKET msgSocket = accept(id, (struct sockaddr*)&from, &fromLen);

	// In case of error
	if (INVALID_SOCKET == msgSocket)
	{
		cout << "Server: Error at accept(): " << WSAGetLastError() << endl;
		return;
	}

	// Add the new socket to the given array
	if (AddSocket(sockets, socketsCount, msgSocket, RECEIVE) == false)
	{
		cout << "\t\tToo many connections, dropped!\n";
		closesocket(id);
	}

	cout << "Server: Client:" << ntohs(from.sin_port) << " is connected." << endl;
}

// Recive message from the given socket
// Update the buffer in the given sockets array
void ReceiveMsg(SocketState* sockets, int* socketsCount, int index)
{
	SOCKET msgSocket = sockets[index].id;
	char message[MAX_DATA];

	// Recive message from the given socket
	int bytesRecv = recv(msgSocket, message, MAX_DATA, 0);

	// In cases of error
	if (SOCKET_ERROR == bytesRecv)
	{
		cout << "Server: Error at recv(): " << WSAGetLastError() << endl;
		closesocket(msgSocket);
		RemoveSocket(sockets, socketsCount, index);
		return;
	}
	// In case connection was closed
	if (bytesRecv == 0)
	{
		closesocket(msgSocket);
		RemoveSocket(sockets, socketsCount, index);
		return;
	}
	else
	{
		// Add the null-terminating to make it a string
		message[bytesRecv] = '\0'; 

		cout << endl << "Server: Recieved: " << bytesRecv << " bytes of \"" << endl << message << "\" message." << endl << endl;
	
		// Add new request to the buffer of the given socket
		sockets[index].buffer.push(HandelRequest(message));

		// Update socket state
		sockets[index].send = SEND;

		// Update last activity
		sockets[index].lastActivityTime = chrono::steady_clock::now();
	}
}

// Send message that answer to the given socket's request
// Update the buffer in the given sockets array
void SendMsg(SocketState* sockets, int index)
{
	int bytesSent = 0;
	SOCKET msgSocket = sockets[index].id;

	// Get the answer for the request in the buffer
	string response = AnswerRequest(sockets[index].buffer.front());

	// Remove the request that was answered  
	sockets[index].buffer.pop();
	
	// Send message to the given socket
	const char* sendBuff = response.c_str();
	bytesSent = send(msgSocket, sendBuff, (int)strlen(sendBuff), 0);

	// In case of error
	if (SOCKET_ERROR == bytesSent)
	{
		cout << "Server: Error at send(): " << WSAGetLastError() << endl;
		return;
	}

	cout << endl << "Server: Sent: " << bytesSent << "\\" << strlen(sendBuff) << " bytes of \"" << endl << sendBuff << "\" message.\n" << endl << endl;

	// Update socket state
	sockets[index].send = IDLE;
}

// Create a new request from the given message and return it
Request HandelRequest(char* message)
{
	Request request;

	// Convert to stream
	istringstream requestStream(message);

	// Extract method, uri
	requestStream >> request.method >> request.uri;

	// Set a defult
	request.langQuery = "en";

	auto posQuery = request.uri.find("?");
	if (posQuery != string::npos)
	{
		// Extract lang query
		auto langPos = request.uri.find("lang=");
		if (langPos != string::npos) 
		{
			// Start of the lang value
			auto langStart = langPos + 5; 
			auto langEnd = request.uri.find("&", langStart);
			if (langEnd == string::npos)
			{
				langEnd = request.uri.length();
			}

			// Check if the lang is valid
			string lang = request.uri.substr(langStart, langEnd - langStart);

			if (lang == "fr" || lang == "he" || lang == "en")
			{
				request.langQuery = lang;
			}
		}

		// Cut the query from the uri
		request.uri = request.uri.substr(0, posQuery);
	}

	request.path = filesystem::current_path().string() + PathPages + request.langQuery + "\\" + request.uri.substr(1, request.uri.length());

	// Convert to string
	string requestString(message);

	// Extract the body of the message
	auto posBody = requestString.find("\r\n\r\n");
	if (posBody != string::npos)
	{
		// Skip the "\r\n\r\n"
		request.content = requestString.substr(posBody + 4);
	}

	return request;
}

// Answer the given request and return it
string AnswerRequest(Request request)
{
	// Check the request
	Validtion validayionRequest = IsValidRequest(request);

	// Answer valid request
	if (validayionRequest == VALID)
	{
		if (request.method == StrMethods[Methods::OPTIONS])
		{
			return Options(request);
		}

		else if (request.method == StrMethods[Methods::GET] || request.method == StrMethods[Methods::HEAD])
		{
			return GetHead(request);
		}

		else if (request.method == StrMethods[Methods::PUT])
		{
			return Put(request);
		}

		else if (request.method == StrMethods[Methods::POST])
		{
			return Post(request);
		}

		else if (request.method == StrMethods[Methods::DELETE_])
		{
			return Delete(request);
		}

		else if (request.method == StrMethods[Methods::TRACE])
		{
			return Trace(request);
		}
	}

	else if (validayionRequest == ROUTE_NOT_FOUND)
	{
		return NotFound(request);
	}

	else
	{
		return NotAllowed(request);
	}
}

// Return the answer for GET or HEAD method for the given request
string GetHead(Request request)
{
	string header;
	string message;

	// Open file 
	ifstream file(request.path);

	// File found with the wanted language
	if (file)
	{
		// Extract the content from the file
		string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
		message = content;

		// Create header
		header = GetHeader(StatusCode::OK, ContentType::HTML, content.size(), "");
	}

	// File not found
	else
	{
		message = "File not found.";

		// Create header
		header = GetHeader(StatusCode::NOT_FOUND, ContentType::PLAIN, message.size(), "");
	}

	// In case of head method, return the header only
	if (request.method == StrMethods[Methods::HEAD])
	{
		return header;
	}

	return header + message;
}

// Return the answer for OPTIONS method
string Options(Request request)
{
	if (request.uri == "/*")
	{
		return GetHeader(StatusCode::NO_CONTENT, ContentType::PLAIN, 0, "Allow: OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE \r\n");
	}
	else
	{
		return GetHeader(StatusCode::NO_CONTENT, ContentType::PLAIN, 0, AllowMethodsStr(request));
	}
}

// Return the answer for DELETE method for the given request
string Delete(Request request)
{
	ifstream file(request.path);
	string header;
	string message;

	// File found
	if (file.is_open())
	{
		// Close file
		file.close();

		// Remove file
		if (remove(request.path.c_str()) == 0)
		{
			message = "File deleted successfully.";
			header = GetHeader(StatusCode::OK, ContentType::PLAIN, message.size(), "");
		}

		// Error
		else
		{
			message = "Failed to delete file.";
			header = GetHeader(StatusCode::SERVER_ERROR, ContentType::PLAIN, message.size(), "");
		}
	}

	// File not found
	else
	{
		message = "File not found.";
		header = GetHeader(StatusCode::NOT_FOUND, ContentType::PLAIN, message.size(), "");
	}

	return header + message;
}

// Return the answer for PUT method for the given request
string Put(Request request)
{
	string header;
	string message;
	bool isExisted = filesystem::exists(request.path);

	// Open or create file
	ofstream file(request.path, std::ofstream::binary);

	// File open successfully
	if (file.is_open()) 
	{
		file << request.content;
		file.close();

		// The file existed before
		if (isExisted)
		{
			message = "File updated successfully.";
			header = GetHeader(StatusCode::OK, ContentType::PLAIN, message.size(), "");
		}
		else 
		{
			message = "File created successfully.";
			header = GetHeader(StatusCode::CREATED, ContentType::PLAIN, message.size(), "");
		}
	}
	else
	{
		message = "Failed to create or update file.";
		header = GetHeader(StatusCode::SERVER_ERROR, ContentType::PLAIN, message.size(), "");
	}

	return header + message;
}

// Return the answer for POST method for the given request and print it
string Post(Request request)
{
	// Print in the server console the content of the request
	cout << request.content;

	string message = "POST run successfully.";
	string header = GetHeader(StatusCode::OK, ContentType::PLAIN, message.size(), "");

	return header + message;
}

// Return the answer for TRACE method for the given request
string Trace(Request request)
{
	string header = GetHeader(StatusCode::OK, ContentType::MESSAGE, request.content.size(), "");

	return header + request.content;
}

// Return message that the method is not allowed
string NotAllowed(Request request)
{
	if (request.method != StrMethods[HEAD])
	{
		string message = "File not allowed.";
		string header = GetHeader(StatusCode::NOT_ALLOWED, ContentType::PLAIN, message.size(), AllowMethodsStr(request));

		return header + message;
	}

	return GetHeader(StatusCode::NOT_ALLOWED, ContentType::PLAIN, 0, AllowMethodsStr(request));
}

// Return message that the method is not found
string NotFound(Request request)
{
	if (request.method != StrMethods[HEAD])
	{
		string message = "File not found.";
		string header = GetHeader(StatusCode::NOT_FOUND, ContentType::PLAIN, message.size(), "");

		return header + message;
	}

	return GetHeader(StatusCode::NOT_FOUND, ContentType::PLAIN, 0, "");
}

// Return string that conatin all the methods allowed in the given for the given request
string AllowMethodsStr(Request request)
{
	vector<Methods> methods = routes.find(request.uri)->second;
	string allow = "Allow: ";

	for (int i = 0; i < methods.size() - 1; i++)
	{
		allow += StrMethods[methods[i]] + ", ";
	}

	allow += StrMethods[methods[methods.size() - 1]] + "\r\n";

	return allow;
}

// Return the validation type of the given request
Validtion IsValidRequest(Request request)
{
	// Search the uri
	auto selectedRoute = routes.find(request.uri);

	if (selectedRoute == routes.end())
	{
		// Not found uri but its put method
		if (request.method == StrMethods[PUT])
		{
			return VALID;
		}
		
		return ROUTE_NOT_FOUND;
	}

	// Search method
	bool found = false;

	for (int i = 0; i < selectedRoute->second.size(); i++)
	{
		if (StrMethods[selectedRoute->second[i]] == request.method)
		{
			found = true;
		}
	}

	if (!found)
	{
		return ROUTE_NOT_ALLOWED;
	}

	return VALID;
}

// Return a header with the given parameters
string GetHeader(StatusCode code, ContentType type, int contentSize, string extra)
{
	string header;

	header = "HTTP/1.1 " + StrStatusCode[code] + "\r\n"
		+ extra 
		+ "Date: " + GetDate()
		+ "Content-Type: " + StrContentType[type] + "\r\n"
		+ "Content-Length: " + to_string(contentSize) + "\r\n"
		+ "\r\n";

	return header;
}

// Return the current date in form of day, month, year, hour, minute and second
string GetDate()
{
	time_t timer;
	time(&timer);

	// Get time in form of string
	string time = ctime(&timer);

	// Replace the \n in the end of the date with \r\n
	time[time.size() - 1] = '\r';
	time += "\n";

	return time;
}

// Check whether the given socket has been inactive for 2 minutes and return the answer
bool isInactive(SocketState socket)
{
	auto currentTime = chrono::steady_clock::now();
	auto elapsedTime = chrono::duration_cast<chrono::minutes>(currentTime - socket.lastActivityTime);
	return elapsedTime >= chrono::minutes(2);
}

// End program with the given message and close the given connection and Winsock, if it is needed.
void CloseProgram(char* message, bool isWSAActive, bool isSocketActive, SOCKET m_socket)
{
	// Print the given message
	cout << message << endl;

	// Closing given connection and Winsock in case it active
	if (isSocketActive)
	{
		closesocket(m_socket);
	}

	// Clean Winsock in case it active
	if (isWSAActive)
	{
		WSACleanup();
	}

	// Close Program
	exit(1);
}
