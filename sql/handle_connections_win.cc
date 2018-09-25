/* Copyright (c) 2018 MariaDB Corporation.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA */


/**
  Accept new client connections on Windows.

  Windows speciality is supporting named pipes, and this does not really work
  with poll() or select() loop, therefore something Windows specific is required.

  The connection loop in this implementation is using asynchronous calls -
  AcceptEx() for sockets, and ConnectNamedPipe() for pipes.

  The loop is finished whenever shutdown event is signaled.
*/

#include <my_global.h>
#include <sql_class.h>
#include <sql_connect.h>
#include <mysqld.h>
#include <log.h>
#include <mswsock.h>
#include <mysql/psi/mysql_socket.h>
#include <violite.h>
#include <sddl.h>

/* From mysqld.cc */
extern HANDLE hEventShutdown;
extern MYSQL_SOCKET base_ip_sock, extra_ip_sock;

static SECURITY_ATTRIBUTES pipe_security;
static HANDLE create_named_pipe();

/**
  Abstract base class for accepting new connection,
  asynchronously (i.e the accept() operation can be posted,
  and result is retrieved later) , and creating a new connection

  Example use
   AcceptHandler acceptor = new SocketHandler(listen_socket);
   acceptor->begin_accept(); // does not block
 
   WaitForSingleObject(acceptor->hEvent);
   SOCKET new_socket = (SOCKET)h->end_accept(GetOverlappedResult(acceptor, ...));
   acceptor->create_connection(socket);


  Concrete implementations for sockets and for pipes.
*/
struct AcceptHandler : public OVERLAPPED
{
  virtual void begin_accept()=0;
  virtual HANDLE end_accept(bool success)=0;
  virtual void create_connection(HANDLE)=0;
  virtual ~AcceptHandler() {};
};

/* Winsock extension finctions. */
static LPFN_ACCEPTEX my_AcceptEx;
static LPFN_GETACCEPTEXSOCKADDRS my_GetAcceptExSockaddrs;

struct SocketAcceptHandler : public AcceptHandler
{
  MYSQL_SOCKET m_listen_socket;
  SOCKET m_accept_socket;
  char m_buffer[2 * sizeof(sockaddr_storage) + 32];

  SocketAcceptHandler(MYSQL_SOCKET listen_socket) :
    AcceptHandler(),
    m_listen_socket(listen_socket),
    m_accept_socket(INVALID_SOCKET)
  {
    hEvent = CreateEvent(0, FALSE, FALSE, 0);
  }

  void begin_accept()
  {
    m_accept_socket = socket(server_socket_ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (m_accept_socket == INVALID_SOCKET)
    {
      sql_perror("socket() call failed.");
      unireg_abort(1);
    }

    DWORD bytes_received;
    BOOL ret = my_AcceptEx(
      m_listen_socket.fd,
      m_accept_socket,
      m_buffer,
      0,
      sizeof(sockaddr_storage) + 16,
      sizeof(sockaddr_storage) + 16,
      &bytes_received,
      this);

    if (ret || GetLastError() == ERROR_IO_PENDING || abort_loop)
      return;

    sql_print_error("my_AcceptEx failed, last error =%u", GetLastError());
    abort();
  }

  HANDLE end_accept(bool success)
  {
    HANDLE handle = (HANDLE)m_accept_socket;
    if (!success)
    {
      /* my_AcceptEx returned error */
      closesocket(m_accept_socket);
      handle = INVALID_HANDLE_VALUE;
    }
    m_accept_socket = INVALID_SOCKET;
    return handle;
  }

  void create_connection(HANDLE handle)
  {
    MYSQL_SOCKET sock{};
    sock.fd = (SOCKET)handle;

#ifdef HAVE_PSI_SOCKET_INTERFACE
    sockaddr *local_addr, *remote_addr;
    int local_addr_len, remote_addr_len;

    my_GetAcceptExSockaddrs(m_buffer,
      0, sizeof(sockaddr_storage) + 16, sizeof(sockaddr_storage) + 16,
      &local_addr, &local_addr_len, &remote_addr, &remote_addr_len);

    sock.m_psi = PSI_SOCKET_CALL(init_socket)
      (key_socket_client_connection, (const my_socket*)&sock.fd, local_addr, local_addr_len);
#endif

    if (setsockopt(sock.fd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
          (char *)&m_listen_socket.fd, sizeof(SOCKET)))
    {
      if (!abort_loop)
      {
        sql_perror("setsockopt(SO_UPDATE_ACCEPT_CONTEXT) failed.");
        abort();
      }
    }
    handle_accepted_socket(sock, m_listen_socket);
  }

  ~SocketAcceptHandler()
  {
    closesocket(m_accept_socket);
    CloseHandle(hEvent);
  }

  /*
    Retrieve the pointer to the Winsock extension functions
    AcceptEx and GetAcceptExSockaddrs.
    We need them for asyncronous accept handling.
  */
  static void init_winsock_extensions()
  {
    SOCKET s = mysql_socket_getfd(base_ip_sock);
    if (s == INVALID_SOCKET)
      s = mysql_socket_getfd(extra_ip_sock);
    if (s == INVALID_SOCKET)
    {
      /* --skip-networking was used*/
      return;
    }
    GUID guid_AcceptEx = WSAID_ACCEPTEX;
    GUID guid_GetAcceptExSockaddrs = WSAID_GETACCEPTEXSOCKADDRS;

    GUID *guids[] = { &guid_AcceptEx, &guid_GetAcceptExSockaddrs };
    void *funcs[] = { &my_AcceptEx, &my_GetAcceptExSockaddrs };
    DWORD bytes;
    for (int i = 0; i < array_elements(guids); i++)
    {
      if (WSAIoctl(s,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        guids[i], sizeof(GUID),
        funcs[i], sizeof(void *),
        &bytes, 0, 0) == -1)
      {
        sql_print_error("WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER) failed");
        unireg_abort(1);
      }
    }
  }
};

struct PipeAcceptHandler : public AcceptHandler
{
  HANDLE m_pipe;

  PipeAcceptHandler(): AcceptHandler(),m_pipe(INVALID_HANDLE_VALUE)
  {
    hEvent = CreateEvent(0, TRUE, FALSE, 0);
  }

  void begin_accept()
  {
    m_pipe = create_named_pipe();
    BOOL connected = ConnectNamedPipe(m_pipe, this);
    if (connected)
    {
      /*  Overlapped ConnectNamedPipe should return zero. */
      sql_perror("Overlapped ConnectNamedPipe() already connected.");
      unireg_abort(1);
      return;
    }
    DWORD last_error = GetLastError();
    switch (last_error)
    {
      case ERROR_PIPE_CONNECTED:
        /* Client is already connected, so signal an event. */
        if (!SetEvent(hEvent))
        {
          sql_perror("SetEvent() failed for connected pipe.");
          unireg_abort(1);
          break;
        }
      case ERROR_IO_PENDING:
        break;
      default:
        sql_perror("ConnectNamedPipe() failed.");
        unireg_abort(1);
        break;
    }
  }

  HANDLE end_accept(bool success)
  {
    if (!success)
    {
      CloseHandle(m_pipe);
      m_pipe = INVALID_HANDLE_VALUE;
    }
    return m_pipe;
  }

  void create_connection(HANDLE handle)
  {
    CONNECT *connect;
    if (!(connect = new CONNECT) || !(connect->vio = vio_new_win32pipe(handle)))
    {
      CloseHandle(handle);
      delete connect;
      statistic_increment(aborted_connects, &LOCK_status);
      statistic_increment(connection_errors_internal, &LOCK_status);
      return;
    }
    connect->host = my_localhost;
    create_new_thread(connect);
  }

  ~PipeAcceptHandler()
  {
    CloseHandle(hEvent);
    if (m_pipe != INVALID_HANDLE_VALUE)
      CloseHandle(m_pipe);
  }

};


/*
  Creates local named pipe instance \\.\pipe\$socket for named pipe connection.
*/
static HANDLE create_named_pipe()
{
  static bool first_instance= true;
  static char pipe_name[512];
  DWORD open_mode = PIPE_ACCESS_DUPLEX |
    FILE_FLAG_OVERLAPPED;

  if (first_instance)
  {
    snprintf(pipe_name, sizeof(pipe_name), "\\\\.\\pipe\\%s", mysqld_unix_port);
    open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
      "S:(ML;; NW;;; LW) D:(A;; FRFW;;; WD)",
      1, &pipe_security.lpSecurityDescriptor, NULL))
    {
      sql_perror("Can't start server : Initialize security descriptor");
      unireg_abort(1);
    }
    pipe_security.nLength = sizeof(SECURITY_ATTRIBUTES);
    pipe_security.bInheritHandle = FALSE;
  }
  HANDLE pipe_handle = CreateNamedPipe(pipe_name,
    open_mode,
    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
    PIPE_UNLIMITED_INSTANCES,
    (int)global_system_variables.net_buffer_length,
    (int)global_system_variables.net_buffer_length,
    NMPWAIT_USE_DEFAULT_WAIT,
    &pipe_security);
  if (pipe_handle == INVALID_HANDLE_VALUE)
  {
    sql_perror("Create named pipe failed");
    unireg_abort(1);
  }
  first_instance = false;
  return pipe_handle;
}

void handle_connections_win()
{
  SocketAcceptHandler::init_winsock_extensions();

  AcceptHandler *handlers[5] = {};
  int n_handlers=0;

  /* shutdown event handler*/
  handlers[n_handlers++] = 0;
  
  if (base_ip_sock.fd != INVALID_SOCKET)
  {
    /* Wait for TCP connections.*/
    handlers[n_handlers++] = new SocketAcceptHandler(base_ip_sock);
  }

  if (extra_ip_sock.fd != INVALID_SOCKET)
  {
    /* Wait for TCP on extra port. */
    handlers[n_handlers++] = new SocketAcceptHandler(extra_ip_sock);
  }

  if (mysqld_unix_port[0] && !opt_bootstrap &&
    opt_enable_named_pipe)
  {
    /*
      Wait for named pipe connections.
      Use 2 handlers, to ensure that clients won't
      get sporadic ERROR_PIPE_BUSY.
    */
    for (int j = 0; j < 2; j++)
      handlers[n_handlers++] = new PipeAcceptHandler();
  }

  HANDLE waithandles[5];
  waithandles[0] = hEventShutdown;
  /* Start waiting for connections.*/
  for (int i = 1; i < n_handlers; i++)
  {
    handlers[i]->begin_accept();
    waithandles[i] = handlers[i]->hEvent;
  }

  for (;;)
  {
    DWORD wait_ret = WaitForMultipleObjects(n_handlers,waithandles, FALSE, INFINITE);
    DBUG_ASSERT(wait_ret != WAIT_FAILED);
    if (wait_ret == WAIT_OBJECT_0)
      /* hEventShutdown was set.*/
      break;

    DWORD bytes;
    AcceptHandler *acceptor = (AcceptHandler *)handlers[wait_ret - WAIT_OBJECT_0];

    BOOL success = GetOverlappedResult(acceptor->hEvent,acceptor,&bytes, FALSE);
    HANDLE sock = acceptor->end_accept(success);

    /* start new async IO*/
    acceptor->begin_accept();

    /* create connection */
    acceptor->create_connection(sock);
  }

  /* Cleanup.*/
  for (int i = 0; i < n_handlers; i++)
    delete handlers[i];

  LocalFree(pipe_security.lpSecurityDescriptor);
}