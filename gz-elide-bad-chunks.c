/* $Id: bin_search.c 6459 2009-08-14 23:17:08Z nlevitt $
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
 
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <zlib.h>
#include <errno.h>
#include <string.h>

#define PROGRAM_NAME "gz-elide-bad-chunks"

static size_t const BUF_SIZE = 4096; 
static unsigned char const GZ_MAGIC[] = { 0x1f, 0x8b };

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

void *
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

size_t 
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

void 
zfree (void *opaque,
       void *address)
{
  fprintf (stderr, PROGRAM_NAME ": info: zfree() opaque=%p address=%p\n", opaque, address);
  DEFAULT_FREE (opaque, address);
}

/* return value must be freed */
z_stream *
init_gzip_input (FILE    *fin,
                 GString *in_buf,
                 GString *out_buf)
{
  z_stream *zs = xmalloc (sizeof (z_stream));

  zs->avail_in = xfread (fin, (void *) in_buf->str, in_buf->allocated_len);
  zs->next_in = (Bytef *) in_buf->str;

  zs->next_out = (Bytef *) out_buf->str;
  zs->avail_out = out_buf->allocated_len;

  zs->zalloc = NULL;
  zs->zfree = NULL;
  zs->opaque = NULL;

  int status = inflateInit (zs);
  if (status != Z_OK)
    {
      fprintf (stdout, PROGRAM_NAME ": error: inflateInit: %s\n", zs->msg);
      exit (1);
    }

  DEFAULT_ZALLOC = zs->zalloc;
  DEFAULT_FREE = zs->zfree;
  zs->zalloc = (alloc_func) zalloc;
  zs->zfree = zfree;

  return zs;
}

static int
get_byte (FILE     *fin, 
          z_stream *zs,
          GString  *in_buf,
          GString  *out_buf)
{
  if (zs->avail_in == 0) 
    {
      /* XXX xfread() ... */
    }
  /*
    {
      errno = 0;
      */
  /*
    if (s->z_eof) return EOF;
    if (s->stream.avail_in == 0) {
        errno = 0;
        s->stream.avail_in = (uInt)fread(s->inbuf, 1, Z_BUFSIZE, s->file);
        if (s->stream.avail_in == 0) {
            s->z_eof = 1;
            if (ferror(s->file)) s->z_err = Z_ERRNO;
            return EOF;
        }
        s->stream.next_in = s->inbuf;
    }
    s->stream.avail_in--;
    return *(s->stream.next_in)++;
    */
  int byte = zs->next_in[0];
  zs->avail_in--;
  zs->next_in++;
  return byte;
}

static void
read_header (FILE     *fin, 
             z_stream *zs,
             GString  *in_buf,
             GString  *out_buf)
{
  if (get_byte (fin, zs, in_buf, out_buf) != GZ_MAGIC[0]
      || get_byte (fin, zs, in_buf, out_buf) != GZ_MAGIC[1])
    {
      fprintf (stderr, PROGRAM_NAME ": error: input doesn't start with gzip magic header\n");
      exit (4);
    }
  /*
  if (zs->avail_in < sizeof (GZ_MAGIC)) 
    {
        ssize_t bytes_read = xread (fin, zs->next_in + zs->avail_in, in_buf->len - zs->avail_in);
        zs->avail_in += bytes_read;
    }
  if (zs->avail_in < sizeof (GZ_MAGIC))
    {
      fprintf (stderr, PROGRAM_NAME ": error: not enough input available?\n");
      exit (5);
    }

  if (memcmp (zs->next_in, GZ_MAGIC, sizeof (GZ_MAGIC)) != 0)
    {
      fprintf (stderr, PROGRAM_NAME ": error: input doesn't start with gzip magic header\n");
      exit (4);
    }

  zs->avail_in -= sizeof (GZ_MAGIC);
  zs->next_in += sizeof (GZ_MAGIC);
  */

#if 0
    /* Check the rest of the gzip header */
    method = get_byte(s);
    flags = get_byte(s);
    if (method != Z_DEFLATED || (flags & RESERVED) != 0) {
        s->z_err = Z_DATA_ERROR;
        return;
    }

    /* Discard time, xflags and OS code: */
    for (len = 0; len < 6; len++) (void)get_byte(s);

    if ((flags & EXTRA_FIELD) != 0) { /* skip the extra field */
        len  =  (uInt)get_byte(s);
        len += ((uInt)get_byte(s))<<8;
        /* len is garbage if EOF but the loop below will quit anyway */
        while (len-- != 0 && get_byte(s) != EOF) ;
    }
    if ((flags & ORIG_NAME) != 0) { /* skip the original file name */
        while ((c = get_byte(s)) != 0 && c != EOF) ;
    }
    if ((flags & COMMENT) != 0) {   /* skip the .gz file comment */
        while ((c = get_byte(s)) != 0 && c != EOF) ;
    }
    if ((flags & HEAD_CRC) != 0) {  /* skip the header crc */
        for (len = 0; len < 2; len++) (void)get_byte(s);
    }
    s->z_err = s->z_eof ? Z_DATA_ERROR : Z_OK;
#endif
}

int
main (int    argc,
      char **argv)
{
  setlocale (LC_ALL, "");

  GString *in_buf = g_string_sized_new (BUF_SIZE);
  GString *out_buf = g_string_sized_new (BUF_SIZE);
  z_stream *zs = init_gzip_input (stdin, in_buf, out_buf);

  read_header (stdin, zs, in_buf, out_buf);

  free (zs);
  g_string_free (out_buf, TRUE);
  g_string_free (in_buf, TRUE);

  return 0;
}
