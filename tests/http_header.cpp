#include <stdio.h>
#include <string.h>

#include <iostream>
#include <unordered_map>

#include "minunit.h"

#include "httputils.hpp"
#include "procutils.h"

typedef std::unordered_map<std::string, std::string> header_map;
typedef header_map::iterator header_map_it;

MU_TEST(test_header_simple)
{
	header_map header;

	/* Correct header */	
	const char* msg = "GET / HTTP/1.1\r\nUser-Agent: curl/7.29.0\r\nHost: 127.0.0.1:12345\r\nAccept: */*\r\n\r\n";
	const char* end = parse_http_req_header(msg, msg + strlen(msg), header);
	mu_assert(end > msg, "header is correct, but parse failed");
	mu_assert(header["Path"] == "/", "header parse failed, check param");
	mu_assert(header["Param"] == "", "header parse failed, check path");



	/* Incomplete header */
	header.clear();
	end = parse_http_req_header(msg, msg + strlen(msg) - 2, header);
	mu_assert(end == msg, "header is incomplete, but parse success");

	/* Incorrect header */	
	header.clear();
	msg = "GET / \r\n\r\n";
	end = parse_http_req_header(msg, msg + strlen(msg), header);
	mu_assert(end <= msg, "header is incorrect, but parse success");
}

MU_TEST(test_header_get)
{
	header_map header;

	/* Correct header */	
	const char* msg = "GET /test.cgi?name=ferret&color=purple HTTP/1.1\r\nUser-Agent: curl/7.29.0\r\nHost: 127.0.0.1:12345\r\nAccept: */*\r\n\r\n";
	const char* end = parse_http_req_header(msg, msg + strlen(msg), header);
	mu_assert(end > msg, "header is correct, but parse failed");
	mu_assert(header["Path"] == "/test.cgi", "header parse failed, check path");
	mu_assert(header["Param"] == "name=ferret&color=purple", "header parse failed, can't extract query param");

	int n_arg;
	char **arg = arg_parse(header["Param"].c_str(), &n_arg, '&');
	if ( n_arg == 2 )
	{
		mu_check( strcmp(arg[0], "name=ferret") == 0 );
		mu_check( strcmp(arg[1], "color=purple") == 0 );
		mu_check( arg[2] == NULL );
	} else
		mu_fail("GET param parse failed");
	arg_free(&arg);

	msg = "GET /test.cgi? HTTP/1.1\r\nUser-Agent: curl/7.29.0\r\nHost: 127.0.0.1:12345\r\nAccept: */*\r\n\r\n";
	end = parse_http_req_header(msg, msg + strlen(msg), header);
	mu_assert(end > msg, "header is correct, but parse failed");
	mu_assert(header["Path"] == "/test.cgi", "header parse failed, check path");
	mu_assert(header["Param"] == "", "header parse failed, check query param");
}

MU_TEST_SUITE(test_header)
{
	MU_RUN_TEST(test_header_simple);
	MU_RUN_TEST(test_header_get);

}

int main(int argc, char *argv[])
{
	MU_RUN_SUITE(test_header);
	MU_REPORT();
	return minunit_status;
}

