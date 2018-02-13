#include <string.h>

#include "httputils.hpp"

const char* parse_http_req_header(const char *msg, const char *msg_end, header_map & header)
{
	const char *head = msg;
	const char *tail = msg;

	// Find request type
	while (tail != msg_end && *tail != ' ' && *tail != '\0') ++tail;
	if (tail == head)
		return NULL;
	header["Type"] = std::string(head, tail);

	// Find path
	while (tail != msg_end && *tail == ' ') ++tail;
        head = tail;
	while (tail != msg_end && *tail != ' ' && *tail != '\0') ++tail;
	if (tail == head)
		return NULL;
	header["Req"] = std::string(head, tail);

	// Find HTTP version
	while (tail != msg_end && *tail == ' ') ++tail;
	head = tail;
	while (tail != msg_end && *tail != '\r' && *tail != '\0') ++tail;
	if (tail == head)
		return NULL;
	header["Version"] = std::string(head, tail);
	if (tail != msg_end - 1 && *tail == '\r')
		tail++;
	else 
		return NULL;
	if (*tail == '\n')
		++tail;
	else
		return NULL;

	// Map all headers from a key to a value
	head = tail;
	while (head != msg_end && *head != '\r')
	{
		while (tail != msg_end && *tail != '\r') ++tail;
			const char *colon = (const char *) memchr(head, ':', tail - head);
		if (colon == NULL) // TODO: malformed headers, what should happen?
			return NULL;
		const char *value = colon + 1;
		while (value != tail && *value == ' ') ++value;
		header[ std::string(head, colon) ] = std::string(value, tail);
		head = tail + 1;
		if (head != msg_end && *head == '\n')
			++head;
		else
			return NULL;
		tail = head;
	}
	if ( msg_end - head < 2 )
		return msg;
	if ( head[1] != '\n' )
		return msg;

	/* extract POST param */
	size_t delim = header["Req"].find('?');
	if (delim == std::string::npos)
	{
		header["Path"] = header["Req"];
		header["Param"] = "";
	} else
	{
		header["Path"] = header["Req"].substr(0, delim);
		header["Param"] = header["Req"].substr(delim + 1);
	}
	
	return head + 2;
}
