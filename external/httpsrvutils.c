#include "httpcodes.h"
#include "httpsrvutils.h"

const char* end_tmpl = "\r\n";

const char* ok_resp_tmpl_s = 
      "200 OK";

const char* ok_resp_tmpl = 
      "%s 200 OK\r\n"
      "Content-Type: %s\r\n"
      "\r\n";
 
const char* not_found_resp_tmpl = 
      "%s 404 Not Found\r\n"
      "Content-type: text/html\r\n"
      "\r\n"
      "<html>\r\n"
      " <body>\r\n"
      "  <h1>Not Found</h1>\r\n"
      "  <p>The requested URL was not found on this server.</p>\r\n"
      " </body>\r\n"
      "</html>\r\n";

const char* bad_req_resp_tmpl = 
      "%s 400 Bad Request\r\n"
      "Content-type: text/html\r\n"
      "\r\n"
      "<html>\r\n"
      " <body>\r\n"
      "  <h1>Bad Request</h1>\r\n"
      "  <p>Bad Request.</p>\r\n"
      " </body>\r\n"
      "</html>\r\n";

const char* unsup_req_resp_tmpl = 
      "%s 400 Bad Request\r\n"
      "Content-type: text/html\r\n"
      "\r\n"
      "<html>\r\n"
      " <body>\r\n"
      "  <h1>Bad Request</h1>\r\n"
      "  <p>Unsupported Request.</p>\r\n"
      " </body>\r\n"
      "</html>\r\n";

const char* internal_err_resp_tmpl = 
      "%s 500 Internal Server Error\r\n"
      "Content-type: text/html\r\n"
      "\r\n"
      "<html>\r\n"
      " <body>\r\n"
      "  <h1>Internal Server Error</h1>\r\n"
      "  <p>Internal Server Error.</p>\r\n"
      " </body>\r\n"
      "</html>\r\n";

