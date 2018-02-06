#ifndef _HTTPUTILS_HPP_
#define _HTTPUTILS_HPP_

#include <string>

/*
#include "sparsepp/spp.h"

typedef spp::sparse_hash_map<std::string, std::string> header_map;
typedef header_map::iterator header_map_it;
*/

#include <unordered_map>

typedef std::unordered_map<std::string, std::string> header_map;
typedef header_map::iterator header_map_it;

bool parse_http_req_header(const char *msg, const char *msg_end, header_map & header);

#endif /* _HTTPUTILS_HPP_ */
