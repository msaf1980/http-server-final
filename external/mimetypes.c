#include <string.h>

#include "mimetypes.h"

const char* mime_type_by_file_ext(char *filename)
{
	char *ext = strrchr(filename, '.');
	if (ext)
	{
		if (strcmp(ext, ".txt") == 0)
			return MIME_TEXT;
		else if (strcmp(ext, ".htm") == 0 || strcmp(ext, ".html") == 0)
			return MIME_HTML;
		else if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0)
			return MIME_IMG_JPG;
		else if (strcmp(ext, ".png") == 0)
			return MIME_IMG_PNG;
		else if (strcmp(ext, ".gif") == 0)
			return MIME_IMG_GIF;
	}
	/* Unknown type, return text/plain */
	return MIME_TEXT;
}
