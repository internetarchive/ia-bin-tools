/* $Id$
 *
 * vim: set sw=2 et:
 *
 * Copyright (C) 2009 Internet Archive
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if 0
typedef struct z_stream_s {
    Bytef    *next_in;  /* next input byte */
    uInt     avail_in;  /* number of bytes available at next_in */
    uLong    total_in;  /* total nb of input bytes read so far */

    Bytef    *next_out; /* next output byte should be put there */
    uInt     avail_out; /* remaining free space at next_out */
    uLong    total_out; /* total nb of bytes output so far */

    char     *msg;      /* last error message, NULL if no error */
    struct internal_state FAR *state; /* not visible by applications */

    alloc_func zalloc;  /* used to allocate the internal state */
    free_func  zfree;   /* used to free the internal state */
    voidpf     opaque;  /* private data object passed to zalloc and zfree */

    int     data_type;  /* best guess about the data type: binary or text */
    uLong   adler;      /* adler32 value of the uncompressed data */
    uLong   reserved;   /* reserved for future use */
} z_stream;
#endif
 
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <zlib.h>
#include <errno.h>
#include <string.h>

#define PROGRAM_NAME "gz-elide-bad-chunks"

/* gzip flag byte */
#define ASCII_FLAG   0x01 /* bit 0 set: file probably ascii text */
#define HEAD_CRC     0x02 /* bit 1 set: header CRC present */
#define EXTRA_FIELD  0x04 /* bit 2 set: extra field present */
#define ORIG_NAME    0x08 /* bit 3 set: original file name present */
#define COMMENT      0x10 /* bit 4 set: file comment present */
#define RESERVED     0xE0 /* bits 5..7: reserved */

static size_t const BUF_SIZE = 4096; 
static unsigned char const GZ_MAGIC[] = { 0x1f, 0x8b };
static alloc_func DEFAULT_ZALLOC = NULL;
static free_func DEFAULT_FREE = NULL;

static void 
zalloc (void   *opaque,
        size_t  count,
        size_t  size)
{
  fprintf (stderr, PROGRAM_NAME ": info: zalloc() opaque=%p count=%zu size=%zu\n", opaque, count, size);
  DEFAULT_ZALLOC (opaque, count, size);
}

static void 
zfree (void *opaque,
       void *address)
{
  fprintf (stderr, PROGRAM_NAME ": info: zfree() opaque=%p address=%p\n", opaque, address);
  DEFAULT_FREE (opaque, address);
}

static void *
xmalloc (size_t size)
{
  void *ptr = malloc (size);
  if (ptr == NULL)
    {
      fprintf (stderr, "gz-elide-bad-chunks: error: virtual memory exhausted\n");
      exit (2);
    }
  return ptr;
}

static size_t 
xfread (FILE   *fin, 
        void   *buf, 
        size_t  nbytes)
{
  errno = 0;
  size_t bytes_read = fread (buf, 1, nbytes, fin);
  if (ferror (fin))
    {
      fprintf (stderr, PROGRAM_NAME ": error: fread: %s\n", g_strerror (errno));
      exit (3);
    }
  return bytes_read;
}

/* 1. if there's no space in the buffer, resets it
 * 2. tries to fill buffer */
static void
refresh_in_buf (FILE     *fin, 
                z_stream *zs,
                GString  *in_buf)
{
  int unused_bytes = in_buf->str + in_buf->allocated_len - ((char *) zs->next_in + zs->avail_in);
  if (unused_bytes == 0)
    {
      memmove (in_buf->str, zs->next_in, zs->avail_in);
      zs->next_in = (Bytef *) in_buf->str;
    }

  unused_bytes = in_buf->str + in_buf->allocated_len - ((char *) zs->next_in + zs->avail_in);
  g_assert (unused_bytes > 0);

  size_t bytes_read = xfread (fin, zs->next_in + zs->avail_in, unused_bytes);
  zs->avail_in += bytes_read;
}

/* return value must be freed */
static z_stream *
init_gzip_input (FILE    *fin,
                 GString *in_buf,
                 GString *out_buf)
{
  z_stream *zs = xmalloc (sizeof (z_stream));

  zs->next_in = (Bytef *) in_buf->str;
  zs->avail_in = 0;
  refresh_in_buf (fin, zs, in_buf);

  zs->next_out = (Bytef *) out_buf->str;
  zs->avail_out = out_buf->allocated_len;

  zs->zalloc = NULL;
  zs->zfree = NULL;
  zs->opaque = NULL;

  /* Comment from gz_open() which uses inflateInit2() this way: "windowBits is
   * passed < 0 to tell that there is no zlib header.  Note that in this case
   * inflate *requires* an extra "dummy" byte after the compressed stream in
   * order to complete decompression and return Z_STREAM_END. Here the gzip
   * CRC32 ensures that 4 bytes are present after the compressed stream." */
  int status = inflateInit2 (zs, -MAX_WBITS);
  if (status != Z_OK)
    {
      fprintf (stderr, PROGRAM_NAME ": error: inflateInit2: %s\n", zs->msg);
      exit (1);
    }

  DEFAULT_ZALLOC = zs->zalloc;
  DEFAULT_FREE = zs->zfree;
  zs->zalloc = (alloc_func) zalloc;
  zs->zfree = zfree;

  return zs;
}

/* returns EOF on eof */
static int
peek_byte (FILE     *fin, 
           z_stream *zs,
           GString  *in_buf)
{
  if (zs->avail_in == 0) 
    refresh_in_buf (fin, zs, in_buf);

  if (zs->avail_in == 0)
    return EOF;

  return (int) (unsigned char) zs->next_in[0];
}

/* returns EOF on eof */
static int
get_byte (FILE     *fin, 
          z_stream *zs,
          GString  *in_buf)
{
  int byte = peek_byte (fin, zs, in_buf);

  if (byte != EOF)
    {
      zs->avail_in--;
      zs->next_in++;
    }

  return byte;
}

static void
read_header (FILE     *fin, 
             z_stream *zs,
             GString  *in_buf,
             GString  *out_buf)
{
  int flags;
  int byte;
  int i;

  for (i = 0; i < sizeof (GZ_MAGIC); i++)
    if (get_byte (fin, zs, in_buf) != GZ_MAGIC[i])
      {
        fprintf (stderr, PROGRAM_NAME ": error: input doesn't start with gzip magic header\n");
        exit (4);
      }

  byte = get_byte (fin, zs, in_buf);
  fprintf (stderr, PROGRAM_NAME ": info: method=0x%02x\n", byte);
  if (byte != Z_DEFLATED)
    {
      fprintf (stderr, PROGRAM_NAME ": error: method != Z_DEFLATED\n");
      exit (5);
    }

  flags = get_byte (fin, zs, in_buf);
  fprintf (stderr, PROGRAM_NAME ": info: flags=0x%02x\n", flags);
  if ((flags & RESERVED) != 0)
    {
      fprintf (stderr, PROGRAM_NAME ": error: flags byte has reserved bits set\n");
      exit (6);
    }
  
  /* discard time, xflags and os code */
  for (i = 0; i < 6; i++) 
    get_byte (fin, zs, in_buf);

  if ((flags & EXTRA_FIELD) != 0)  
    { 
      fprintf (stderr, PROGRAM_NAME ": info: flags byte indicates there is an extra field\n");

      unsigned len = (unsigned) get_byte (fin, zs, in_buf);
      len += ((unsigned) get_byte (fin, zs, in_buf)) << 8;

      /* len is garbage if EOF but the loop below will quit anyway */
      while (len-- != 0 && get_byte (fin, zs, in_buf) != EOF);
    }

  if ((flags & ORIG_NAME) != 0) 
    {
      GString *tmp_str = g_string_new ("");
      for (byte = get_byte (fin, zs, in_buf); 
           byte != 0 && byte != EOF; 
           byte = get_byte (fin, zs, in_buf))
        g_string_append_c (tmp_str, byte);
      fprintf (stderr, PROGRAM_NAME ": info: original name of gzipped file: %s\n", tmp_str->str);
      g_string_free (tmp_str, TRUE);
    }

  if ((flags & COMMENT) != 0) 
    {
      GString *tmp_str = g_string_new ("");
      for (byte = get_byte (fin, zs, in_buf); 
           byte != 0 && byte != EOF; 
           byte = get_byte (fin, zs, in_buf))
        g_string_append_c (tmp_str, byte);
      fprintf (stderr, PROGRAM_NAME ": info: gzip header comment: %s\n", tmp_str->str);
      g_string_free (tmp_str, TRUE);
    }

    if ((flags & HEAD_CRC) != 0) 
      { 
        int head_crc[2];
        head_crc[0] = get_byte (fin, zs, in_buf);
        head_crc[1] = get_byte (fin, zs, in_buf);
      }

    /*
    if (peek_byte (fin, zs, in_buf) == EOF)
      return EOF;

    return 0;
    */
}

static char const *
z_status_string (int z_status)
{
  static char buf[40];
  switch (z_status)
    {
      case Z_OK: return "Z_OK";
      case Z_STREAM_END: return "Z_STREAM_END";
      case Z_NEED_DICT: return "Z_NEED_DICT";
      case Z_ERRNO: return "Z_ERRNO";
      case Z_STREAM_ERROR: return "Z_STREAM_ERROR";
      case Z_DATA_ERROR: return "Z_DATA_ERROR";
      case Z_MEM_ERROR: return "Z_MEM_ERROR";
      case Z_BUF_ERROR: return "Z_BUF_ERROR";
      case Z_VERSION_ERROR: return "Z_VERSION_ERROR";
      default:
        snprintf (buf, sizeof (buf), "unknown status %d", z_status);
        return buf;
    }
}

/* returns number of uncompressed bytes read */
static int
uncompress_data (FILE     *fin, 
                 z_stream *zs,
                 GString  *in_buf,
                 GString  *out_buf)
{
  int avail_out_before = zs->avail_out;

  int status = inflate(zs, Z_NO_FLUSH);
  fprintf (stderr, PROGRAM_NAME ": info: inflate returned %s\n", z_status_string (status));

  return avail_out_before - zs->avail_out;
}

int
main (int    argc,
      char **argv)
{
  setlocale (LC_ALL, "");

  /* all the GString stuff wants a terminating null character, so it even adds
   * space in g_string_sized_new(), thus the BUF_SIZE-1 */
  GString *in_buf = g_string_sized_new (BUF_SIZE - 1);
  GString *out_buf = g_string_sized_new (BUF_SIZE - 1);

  z_stream *zs = init_gzip_input (stdin, in_buf, out_buf);

  read_header (stdin, zs, in_buf, out_buf);

  int uncompressed_bytes;
  while ((uncompressed_bytes = uncompress_data (stdin, zs, in_buf, out_buf)) > 0)
    fprintf (stderr, PROGRAM_NAME ": info: %d uncompressed bytes read\n", uncompressed_bytes);
  fprintf (stderr, PROGRAM_NAME ": info: %d uncompressed bytes read\n", uncompressed_bytes);

  free (zs);
  g_string_free (out_buf, TRUE);
  g_string_free (in_buf, TRUE);

  return 0;
}
