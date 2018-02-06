#ifndef _MIMETYPES_H_
#define _MIMETYPES_H_

#define MIME_TEXT "text/plain"
#define MIME_HTML "text/html"
#define MIME_IMG_GIF "image/gif"
#define MIME_IMG_PNG "image/png"
#define MIME_IMG_JPG "image/jpeg"
#define MIME_IMG_BMP "image/bmp"

#ifdef __cplusplus
extern "C" {
#endif

const char *mime_type_by_file_ext(char *filename);

#ifdef __cplusplus
}
#endif

#endif /* _MIMETYPES_H_ */
