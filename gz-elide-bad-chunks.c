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

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <zlib.h>
#include <errno.h>
#include <string.h>

#define PROGRAM_NAME "gz-elide-bad-chunks"

struct gzelide_state
{
  FILE     *fin;
  FILE     *fout;
  z_stream *zs;
  GString  *in_buf;
  GString  *out_buf;
  GString  *chunk_buf;
};

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
static void
init_z_stream (struct gzelide_state *state)
{
  state->zs = xmalloc (sizeof (z_stream));

  state->zs->next_in = (Bytef *) state->in_buf->str;
  state->zs->avail_in = 0;

  state->zs->next_out = (Bytef *) state->out_buf->str;
  state->zs->avail_out = state->out_buf->allocated_len;

  state->zs->zalloc = NULL;
  state->zs->zfree = NULL;
  state->zs->opaque = NULL;

  /* Comment from copied gz_open(): "windowBits is passed < 0 to tell that
   * there is no zlib header.  Note that in this case inflate *requires* an
   * extra "dummy" byte after the compressed stream in order to complete
   * decompression and return Z_STREAM_END. Here the gzip CRC32 ensures that 4
   * bytes are present after the compressed stream." */
  int status = inflateInit2 (state->zs, -MAX_WBITS);
  if (status != Z_OK)
    {
      fprintf (stderr, PROGRAM_NAME ": error: inflateInit2: %s\n", state->zs->msg);
      exit (1);
    }

  DEFAULT_ZALLOC = state->zs->zalloc;
  DEFAULT_FREE = state->zs->zfree;
  state->zs->zalloc = (alloc_func) zalloc;
  state->zs->zfree = zfree;
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
next_chunk_byte (struct gzelide_state *state)
{
  int byte = peek_byte (state->fin, state->zs, state->in_buf);

  if (byte != EOF)
    {
      state->zs->avail_in--;
      state->zs->next_in++;
      g_string_append_c (state->chunk_buf, byte);
    }

  return byte;
}

/* returns chunk size, or 0 on EOF, or -1 on bad gzip data */
static int
read_chunk (struct gzelide_state *state)
{
  g_string_set_size (state->chunk_buf, 0);

  int i;
  for (i = 0; i < sizeof (GZ_MAGIC); i++)
    if (next_chunk_byte (state) != GZ_MAGIC[i])
      {
        fprintf (stderr, PROGRAM_NAME ": info: purported gzip chunk doesn't start with gzip magic header\n");
        return -1;
      }

  int byte = next_chunk_byte (state);
  fprintf (stderr, PROGRAM_NAME ": info: method=0x%02x\n", byte);
  if (byte != Z_DEFLATED)
    {
      fprintf (stderr, PROGRAM_NAME ": info: purported gzip chunk has method != Z_DEFLATED\n");
      return -1;
    }

  int flags = next_chunk_byte (state);
  fprintf (stderr, PROGRAM_NAME ": info: flags=0x%02x\n", flags);
  if ((flags & RESERVED) != 0)
    {
      fprintf (stderr, PROGRAM_NAME ": info: purported gzip chunk has reserved bits set\n");
      return -1;
    }
  
  /* discard time, xflags and os code */
  for (i = 0; i < 6; i++) 
    next_chunk_byte (state);

  if ((flags & EXTRA_FIELD) != 0)  
    { 
      fprintf (stderr, PROGRAM_NAME ": info: flags byte indicates there is an extra field\n");

      unsigned len = (unsigned) next_chunk_byte (state);
      len += ((unsigned) next_chunk_byte (state)) << 8;

      /* len is garbage if EOF but the loop below will quit anyway */
      while (len-- > 0 && next_chunk_byte (state) != EOF);
    }

  if ((flags & ORIG_NAME) != 0) 
    {
      GString *tmp_str = g_string_new ("");
      for (byte = next_chunk_byte (state); 
           byte != 0 && byte != EOF; 
           byte = next_chunk_byte (state))
        g_string_append_c (tmp_str, byte);
      fprintf (stderr, PROGRAM_NAME ": info: original name of gzipped file: %s\n", tmp_str->str);
      g_string_free (tmp_str, TRUE);
    }

  if ((flags & COMMENT) != 0) 
    {
      GString *tmp_str = g_string_new ("");
      for (byte = next_chunk_byte (state); 
           byte != 0 && byte != EOF; 
           byte = next_chunk_byte (state))
        g_string_append_c (tmp_str, byte);
      fprintf (stderr, PROGRAM_NAME ": info: gzip header comment: %s\n", tmp_str->str);
      g_string_free (tmp_str, TRUE);
    }

  if ((flags & HEAD_CRC) != 0) 
    { 
      int head_crc[2];
      head_crc[0] = next_chunk_byte (state);
      head_crc[1] = next_chunk_byte (state);
      fprintf (stderr, PROGRAM_NAME ": info: gzip head crc: %02x%02x\n", head_crc[0], head_crc[1]);
    }

  /* finished with header, on to data */

  /* inflate() returns Z_OK if some progress has been made (more input
   * processed or more output produced), Z_STREAM_END if the end of the
   * compressed data has been reached and all uncompressed output has been
   * produced, Z_NEED_DICT if a preset dictionary is needed at this point,
   * Z_DATA_ERROR if the input data was corrupted (input stream not conforming
   * to the zlib format or incorrect check value), Z_STREAM_ERROR if the stream
   * structure was inconsistent (for example if next_in or next_out was NULL),
   * Z_MEM_ERROR if there was not enough memory, Z_BUF_ERROR if no progress is
   * possible or if there was not enough room in the output buffer when
   * Z_FINISH is used. Note that Z_BUF_ERROR is not fatal, and inflate() can be
   * called again with more input and more output space to continue
   * decompressing. If Z_DATA_ERROR is returned, the application may then call
   * inflateSync() to look for a good compression block if a partial recovery
   * of the data is desired.  */
  while (1)
    {
      unsigned char *read_start = state->zs->next_in;

      int status = inflate (state->zs, Z_NO_FLUSH);
      if (status == Z_DATA_ERROR)
        {
          fprintf (stderr, PROGRAM_NAME ": info: purported gzip chunk has bad data: %s\n", state->zs->msg);
          return -1;
        }
      else if (status == Z_NEED_DICT)
        {
          fprintf (stderr, PROGRAM_NAME ": error: inflate returned Z_NEED_DICT: contingency unimplemented\n");
          exit (5);
        }
      else if (status != Z_OK && status != Z_STREAM_END)
        {
          fprintf (stderr, PROGRAM_NAME ": error: inflate returned unexpected status %d: probably indicates a bug in this program\n", status);
          exit (6);
        }

      g_string_append_len (state->chunk_buf, (char *) read_start, state->zs->next_in - read_start);  

      refresh_in_buf (state->fin, state->zs, state->in_buf);
      state->zs->next_out = (unsigned char *) state->out_buf->str;
      state->zs->avail_out = state->out_buf->allocated_len;

      if (status == Z_STREAM_END)
        {
          /* reached the end of the chunk */
          return state->chunk_buf->len;
        }
    }

  return state->chunk_buf->len;
}

static int
find_magic (struct gzelide_state *state)
{
  fprintf (stderr, PROGRAM_NAME ": error: find_magic: unimplemented\n");
  exit (4);
}

#if 0
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
#endif

int
main (int    argc,
      char **argv)
{
  setlocale (LC_ALL, "");

  struct gzelide_state state;
  state.fin = stdin;
  state.fout = stdout;
  state.zs = NULL;
  /* all the GString stuff wants a terminating null character, so it even adds
   * space in g_string_sized_new(), thus the BUF_SIZE-1 */
  state.in_buf = g_string_sized_new (BUF_SIZE - 1);
  state.out_buf = g_string_sized_new (BUF_SIZE - 1);
  state.chunk_buf = g_string_new ("");

  init_z_stream (&state);

  while (1)
    {
      int chunk_size = read_chunk (&state);
      if (chunk_size > 0) 
        {
          g_assert (chunk_size == state.chunk_buf->len);
          fprintf (stderr, PROGRAM_NAME ": info: writing good chunk of length %d\n", chunk_size);
          /* fwrite (state.chunk_buf->str, 1, state.chunk_buf->len, state.fout); */
        }
      else if (chunk_size < 0)
        {
          fprintf (stderr, PROGRAM_NAME ": info: eliding bad chunk\n");
          find_magic (&state);
        }
      else
        {
          fprintf (stderr, PROGRAM_NAME ": info: reached end of input\n");
          break;
        }
    }

  /*
  read_header (stdin, zs, in_buf, out_buf);

  int uncompressed_bytes;
  while ((uncompressed_bytes = uncompress_data (stdin, zs, in_buf, out_buf)) > 0)
    fprintf (stderr, PROGRAM_NAME ": info: %d uncompressed bytes read\n", uncompressed_bytes);
  fprintf (stderr, PROGRAM_NAME ": info: %d uncompressed bytes read\n", uncompressed_bytes);
  */

  free (state.zs);
  g_string_free (state.out_buf, TRUE);
  g_string_free (state.in_buf, TRUE);
  g_string_free (state.chunk_buf, TRUE);

  return 0;
}
