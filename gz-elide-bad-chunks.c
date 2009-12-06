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
  FILE          *fin;
  FILE          *fout;
  z_stream      *zs;
  GString       *in_buf;
  GString       *out_buf;
  GString       *chunk_buf;
  off_t          chunk_offset;
  unsigned long  crc;
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
}

/* returns EOF on eof */
static int
peek_byte (struct gzelide_state *state)
{
  if (state->zs->avail_in == 0) 
    refresh_in_buf (state->fin, state->zs, state->in_buf);

  if (state->zs->avail_in == 0)
    return EOF;

  return (int) (unsigned char) state->zs->next_in[0];
}

/* returns EOF on eof */
static int 
next_chunk_byte (struct gzelide_state *state)
{
  int byte = peek_byte (state);

  if (byte != EOF)
    {
      state->zs->avail_in--;
      state->zs->next_in++;
      g_string_append_c (state->chunk_buf, byte);
    }

  return byte;
}

static gboolean
read_header (struct gzelide_state *state)
{
  int i;
  for (i = 0; i < sizeof (GZ_MAGIC); i++)
    if (next_chunk_byte (state) != GZ_MAGIC[i])
      {
        /* fprintf (stderr, PROGRAM_NAME ": info: purported gzip chunk doesn't start with gzip magic header\n"); */
        return FALSE;
      }

  int byte = next_chunk_byte (state);
  if (byte != Z_DEFLATED)
    {
      /* fprintf (stderr, PROGRAM_NAME ": info: purported gzip chunk has method != Z_DEFLATED\n"); */
      return FALSE;
    }

  int flags = next_chunk_byte (state);
  if ((flags & RESERVED) != 0)
    {
      /* fprintf (stderr, PROGRAM_NAME ": info: purported gzip chunk has reserved bits set\n"); */
      return FALSE;
    }
  
  /* discard time, xflags and os code */
  for (i = 0; i < 6; i++) 
    next_chunk_byte (state);

  if ((flags & EXTRA_FIELD) != 0)  
    { 
      /* fprintf (stderr, PROGRAM_NAME ": info: flags byte indicates there is an extra field\n"); */

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
      /* fprintf (stderr, PROGRAM_NAME ": info: original name of gzipped file: %s\n", tmp_str->str); */
      g_string_free (tmp_str, TRUE);
    }

  if ((flags & COMMENT) != 0) 
    {
      GString *tmp_str = g_string_new ("");
      for (byte = next_chunk_byte (state); 
           byte != 0 && byte != EOF; 
           byte = next_chunk_byte (state))
        g_string_append_c (tmp_str, byte);
      /* fprintf (stderr, PROGRAM_NAME ": info: gzip header comment: %s\n", tmp_str->str); */
      g_string_free (tmp_str, TRUE);
    }

  if ((flags & HEAD_CRC) != 0) 
    { 
      int head_crc[2];
      head_crc[0] = next_chunk_byte (state);
      head_crc[1] = next_chunk_byte (state);
      /* fprintf (stderr, PROGRAM_NAME ": info: gzip head crc: %02x%02x\n", head_crc[0], head_crc[1]); */
    }

  return TRUE;
}

static gboolean
read_data (struct gzelide_state *state)
{
  if (inflateReset (state->zs) != Z_OK) 
    {
      fprintf (stderr, PROGRAM_NAME ": error: inflateReset failed: probably indicates a bug in this program\n");
      exit (6);
    }

  state->crc = crc32 (0l, NULL, 0);

  int status = Z_OK;
  while (status != Z_STREAM_END)
    {
      refresh_in_buf (state->fin, state->zs, state->in_buf);
      state->zs->next_out = (unsigned char *) state->out_buf->str;
      state->zs->avail_out = state->out_buf->allocated_len;

      unsigned char *next_in_before = state->zs->next_in;
      unsigned char *next_out_before = state->zs->next_out;

      status = inflate (state->zs, Z_NO_FLUSH);

      if (status == Z_DATA_ERROR)
        {
          /* fprintf (stderr, PROGRAM_NAME ": info: purported gzip chunk has bad data: %s\n", state->zs->msg); */
          return FALSE;
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

      g_string_append_len (state->chunk_buf, (char *) next_in_before, state->zs->next_in - next_in_before);  

      state->crc = crc32 (state->crc, next_out_before, state->zs->next_out - next_out_before);
    }

  return TRUE;
}

static gboolean
read_footer (struct gzelide_state *state)
{
  unsigned long purported_crc = next_chunk_byte (state);
  purported_crc += ((unsigned) next_chunk_byte (state)) << 8;
  purported_crc += ((unsigned) next_chunk_byte (state)) << 16;
  purported_crc += ((unsigned) next_chunk_byte (state)) << 24;

  if (purported_crc != state->crc)
    {
      /*
      fprintf (stderr, PROGRAM_NAME ": info: purported crc %lu does not match computed crc %lu\n", 
          purported_crc, state->crc);
          */
      return FALSE;
    }

  unsigned long purported_uncompressed_bytes = next_chunk_byte (state);
  purported_uncompressed_bytes += ((unsigned) next_chunk_byte (state)) << 8;
  purported_uncompressed_bytes += ((unsigned) next_chunk_byte (state)) << 16;
  if (peek_byte (state) == EOF)
    {
      /* fprintf (stderr, PROGRAM_NAME ": info: purported gzip chunk ends in middle of 8 byte footer\n"); */
      return FALSE;
    }
  purported_uncompressed_bytes += ((unsigned) next_chunk_byte (state)) << 24;

  if (purported_uncompressed_bytes != state->zs->total_out)
    {
      /*
      fprintf (stderr, PROGRAM_NAME ": info: purported uncompressed size %lu bytes does not match actual uncompressed size %lu bytes\n", 
          purported_uncompressed_bytes, state->zs->total_out); 
          */
      return FALSE;
    }

  return TRUE;
}


/* returns true if it reads a valid gzip chunk, false if not */
static gboolean
read_chunk (struct gzelide_state *state)
{
  g_string_set_size (state->chunk_buf, 0);
  state->chunk_offset = ftello (state->fin) - state->zs->avail_in;

  return read_header (state) 
    && read_data (state)
    && read_footer (state);
}

/* returns true if magic found, false if eof */
static gboolean
find_magic (struct gzelide_state *state)
{
  while (TRUE)
    {
      if (state->zs->avail_in < 2)
        refresh_in_buf (state->fin, state->zs, state->in_buf);

      if (state->zs->avail_in < 2)
        {
          if (state->zs->avail_in == 1)
            {
              /* advance to eof */
              state->zs->avail_in--;
              state->zs->next_in++;
              g_assert (peek_byte (state) == EOF);
            }
          return FALSE;
        }

      if (state->zs->next_in[0] == GZ_MAGIC[0])
        if (state->zs->next_in[1] == GZ_MAGIC[1])
          return TRUE;

      state->zs->avail_in--;
      state->zs->next_in++;
    }
}

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

  off_t elision_offset = -1;
  while (peek_byte (&state) != EOF)
    {
      if (read_chunk (&state))
        {
          if (elision_offset > 0)
            {
              fprintf (stderr, PROGRAM_NAME ": info: elided %lld bytes starting at offset %lld\n", 
                  (long long) (state.chunk_offset - elision_offset), (long long) elision_offset);
              elision_offset = -1;
            }
          /*
          fprintf (stderr, PROGRAM_NAME ": info: writing good chunk offset=%lld length=%ld\n", 
              state.chunk_offset, state.chunk_buf->len);
              */
          fwrite (state.chunk_buf->str, 1, state.chunk_buf->len, state.fout);
        }
      else
        {
          /* fprintf (stderr, PROGRAM_NAME ": info: eliding bad chunk\n"); */
          elision_offset = state.chunk_offset;
          find_magic (&state);
        }
    }

  if (elision_offset > 0)
    {
      fprintf (stderr, PROGRAM_NAME ": info: elided %lld bytes starting at offset %lld\n", 
          (long long) (ftello (state.fin) - elision_offset), (long long) elision_offset);
    }

  free (state.zs);
  g_string_free (state.out_buf, TRUE);
  g_string_free (state.in_buf, TRUE);
  g_string_free (state.chunk_buf, TRUE);

  return 0;
}
