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
#include <glib/gstdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <zlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct 
{
  FILE          *fin;
  FILE          *fout;
  z_stream      *zs;
  GString       *in_buf;
  GString       *out_buf;
  off_t          good_chunk_offset;
  off_t          bad_chunk_offset;
  unsigned long  crc;
  char          *split_dir;
  int            dumped_chunks;
  off_t          dumped_bytes;
} 
GzipChunksState;

/* gzip flag byte */
static int const ASCII_FLAG  = 0x01; /* bit 0 set: file probably ascii text */
static int const HEAD_CRC    = 0x02; /* bit 1 set: header CRC present */
static int const EXTRA_FIELD = 0x04; /* bit 2 set: extra field present */
static int const ORIG_NAME   = 0x08; /* bit 3 set: original file name present */
static int const COMMENT     = 0x10; /* bit 4 set: file comment present */
static int const RESERVED    = 0xE0; /* bits 5..7: reserved */

static size_t const INITIAL_BUF_SIZE = 4096; 
static size_t const MAX_BUF_SIZE = 512 * 1024;
static unsigned char const GZ_MAGIC[] = { 0x1f, 0x8b };

static struct
{
  gboolean  verbose;
  char     *output_file;
  gboolean  invalid;
  gboolean  split;
  char     *split_dir;
  off_t     start_offset;
  off_t     end_offset;
} 
options = { FALSE, NULL, FALSE, FALSE, NULL, 0, -1 };

static GOptionEntry entries[] =
{
  { "verbose", '\0', 0, G_OPTION_ARG_NONE, &options.verbose, "Report verbosely on gzip doings", NULL },
  { "output", 'o', 0, G_OPTION_ARG_STRING, &options.output_file, "Write to specified file (default is stdout)", "FILE" },
  { "invalid", 'x', 0, G_OPTION_ARG_NONE, &options.invalid, "Invert the operation: write chunks that are NOT valid gzip chunks", NULL },
  { "split", '\0', 0, G_OPTION_ARG_NONE, &options.split, "Write each chunk to a separate file, in a randomly named directory in temp space", NULL },
  { "split-dir", 'd', 0, G_OPTION_ARG_STRING, &options.split_dir, "Write each chunk separate file in the specified directory", "PATH" },
  { "start", '\0', 0, G_OPTION_ARG_INT64, &options.start_offset, "Start processing input at specified byte offset", "OFFSET" },
  { "end", '\0', 0, G_OPTION_ARG_INT64, &options.end_offset, "Stop processing input at specified byte offset", "OFFSET" },
  { NULL }
};

static void
G_GNUC_PRINTF (1, 2)
info (char const *format,
      ...)
{
  if (options.verbose)
    {
      fprintf (stderr, "%s: info: ", g_get_prgname ());

      va_list args;
      va_start (args, format);
      vfprintf (stderr, format, args);
      va_end (args);

      fputc ('\n', stderr);
    }
}

static void
G_GNUC_PRINTF (1, 2)
die (char const *format,
     ...)
{
  fprintf (stderr, "%s: error: ", g_get_prgname ());

  va_list args;
  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);

  fputc ('\n', stderr);

  exit (1);
}

static void *
xmalloc (size_t size)
{
  void *ptr = malloc (size);
  if (ptr == NULL)
    die ("virtual memory exhausted");
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
    die ("fread: %s", g_strerror (errno));
  return bytes_read;
}

static void
free_state_stuff (GzipChunksState *state)
{
  free (state->zs);
  g_string_free (state->out_buf, TRUE);
  g_string_free (state->in_buf, TRUE);
}

static void
init_state (GzipChunksState   *state,
            int               *argc,
            char            ***argv)
{
  state->fin = NULL;
  state->fout = NULL;
  state->zs = NULL;
  state->in_buf = NULL;
  state->out_buf = NULL;
  state->good_chunk_offset = -1;
  state->bad_chunk_offset = -1;
  state->crc = 0;
  state->split_dir = NULL;
  state->dumped_chunks = 0;
  state->dumped_bytes = 0;

  GOptionContext *context = g_option_context_new ("FILE");
  GError *error = NULL;

  g_option_context_add_main_entries (context, entries, NULL);
  g_option_context_set_summary (context, "Identifies valid gzip chunks in the input and writes them verbatim to the output.");

  g_option_context_set_description (context, 
      "This tool dumps valid gzip chunks from the input. To put it another way, it\n"
      "elides invalid data.\n"
      "\n"
      "Examples of usage:\n"
      "\n"
      "  # salvage good records from a bad warc.gz\n"
      "  gzip-chunks bad.warc.gz > repaired.warc.gz\n"
      "\n"
      "  # save invalid gzip chunks toward end of file for inspection\n"
      "  gzip-chunks --invalid --split --start=90000000 bad.warc.gz\n");   

  if (!g_option_context_parse (context, argc, argv, &error))
    {
      fprintf (stderr, "%s: %s\n\n", g_get_prgname(), error->message);
      fputs (g_option_context_get_help (context, TRUE, NULL), stderr);
      exit (1);
    }

  if (*argc != 2)
    {
      fprintf (stderr, "%s: error: exactly one input filename required\n\n", g_get_prgname ());
      fputs (g_option_context_get_help (context, TRUE, NULL), stderr);
      exit (1);
    }

  /* "--split --split-dir=foo" is the same as "--split-dir=foo */
  if (*argc == 2)
    {
      errno = 0;
      state->fin = fopen ((*argv)[1], "rb");
      if (state->fin == NULL)
        die ("%s: %s", (*argv)[1], g_strerror (errno));
    }
  else
    state->fin = stdin;

  if (options.split_dir)
    {
      state->split_dir = options.split_dir;

      /* XXX if this fails let error message come up later */
      mkdir (state->split_dir, 0755);
    }
  else if (options.split)
    {
      GString *template = g_string_new ("");
      char *short_filename;
      if (state->fin == stdin)
        short_filename = g_strdup ("stdin");
      else
        short_filename = g_path_get_basename ((*argv)[1]);

      g_string_printf (template, "%s/gzip-chunks-%s-XXXXXX", g_get_tmp_dir (), short_filename);

      errno = 0;
      state->split_dir = mkdtemp (template->str);
      if (state->split_dir == NULL)
        die ("mkdtemp: unable to create temp dir: %s", g_strerror (errno));

      printf ("%s: dumping %s gzip chunks into %s (use --verbose for more info)\n", 
          g_get_prgname (), options.invalid ? "invalid" : "valid", state->split_dir);
    }
  if (state->split_dir)
    state->fout = NULL;

  if (options.output_file && options.split)
    die ("--output and --split cannot be used together");
  else if (options.output_file && options.split_dir)
    die ("--output and --split-dir cannot be used together");

  if (options.output_file != NULL)
    {
      errno = 0;
      state->fout = fopen (options.output_file, "wb");
      if (state->fout == NULL) 
        die ("%s: %s", options.output_file, g_strerror (errno));
    }
  else if (state->split_dir == NULL)
    state->fout = stdout;

  if (state->fout != NULL && isatty (fileno (state->fout)))
    die ("refusing to write binary data to a tty");

  g_option_context_free (context);

  /* all the GString stuff wants a terminating null character, so it even adds
   * space in g_string_sized_new(), thus the INITIAL_BUF_SIZE-1 */
  state->in_buf = g_string_sized_new (INITIAL_BUF_SIZE - 1);
  state->out_buf = g_string_sized_new (INITIAL_BUF_SIZE - 1);

  state->zs = xmalloc (sizeof (z_stream));

  state->zs->next_in = (Bytef *) state->in_buf->str;
  state->zs->avail_in = 0;

  state->zs->next_out = (Bytef *) state->out_buf->str;
  state->zs->avail_out = state->out_buf->allocated_len;

  state->zs->zalloc = NULL;
  state->zs->zfree = NULL;
  state->zs->opaque = NULL;

  /* Comment from zlib gzio.c gz_open(): "windowBits is passed < 0 to tell that
   * there is no zlib header.  Note that in this case inflate *requires* an
   * extra "dummy" byte after the compressed stream in order to complete
   * decompression and return Z_STREAM_END. Here the gzip CRC32 ensures that 4
   * bytes are present after the compressed stream." */
  int status = inflateInit2 (state->zs, -MAX_WBITS);
  if (status != Z_OK)
    die ("inflateInit2: %s", state->zs->msg);
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

/* returns EOF on eof */
static int
peek_byte (GzipChunksState *state)
{
  if (state->zs->avail_in == 0) 
    refresh_in_buf (state->fin, state->zs, state->in_buf);

  if (state->zs->avail_in == 0)
    return EOF;

  return (int) (unsigned char) state->zs->next_in[0];
}

/* returns EOF on eof */
static int 
get_byte (GzipChunksState *state)
{
  int byte = peek_byte (state);

  if (byte != EOF)
    {
      state->zs->avail_in--;
      state->zs->next_in++;
    }

  return byte;
}

static gboolean
check_gzip_header (GzipChunksState *state)
{
  int i;
  for (i = 0; i < sizeof (GZ_MAGIC); i++)
    if (get_byte (state) != GZ_MAGIC[i])
      {
        info ("purported gzip chunk doesn't start with gzip magic header");
        return FALSE;
      }

  int byte = get_byte (state);
  if (byte != Z_DEFLATED)
    {
      info ("purported gzip chunk has method != Z_DEFLATED");
      return FALSE;
    }

  int flags = get_byte (state);
  if ((flags & RESERVED) != 0)
    {
      info ("purported gzip chunk has reserved bits set");
      return FALSE;
    }
  
  /* discard time, xflags and os code */
  for (i = 0; i < 6; i++) 
    byte = get_byte (state);

  if (byte == EOF)
    {
      info ("input ends in gzip time / xflags / os code");
      return FALSE;
    }

  if ((flags & EXTRA_FIELD) != 0)  
    { 
      unsigned len = (unsigned) get_byte (state);
      len += ((unsigned) get_byte (state)) << 8;

      for (i = 0; i < len; i++)
        byte = get_byte (state);

      if (byte == EOF)
        {
          info ("input ends in gzip extra field");
          return FALSE;
        }
    }

  if ((flags & ORIG_NAME) != 0) 
    {
      for (byte = get_byte (state); 
          byte != 0 && byte != EOF; 
          byte = get_byte (state));

      if (byte == EOF)
        {
          info ("input ends in gzip extra field");
          return FALSE;
        }
    }

  if ((flags & COMMENT) != 0) 
    {
      for (byte = get_byte (state); 
          byte != 0 && byte != EOF; 
          byte = get_byte (state));

      if (byte == EOF)
        {
          info ("input ends in gzip comment field");
          return FALSE;
        }
    }

  if ((flags & HEAD_CRC) != 0) 
    {
      byte = get_byte (state);
      byte = get_byte (state);

      if (byte == EOF)
        {
          info ("input ends in gzip comment field");
          return FALSE;
        }
    }

  return TRUE;
} 

static void
expand_buffers (GzipChunksState *state)
{
  int next_in_offset = (char *) state->zs->next_in - (char *) state->in_buf->str;
  state->in_buf->len = state->in_buf->allocated_len;
  g_string_set_size (state->in_buf, 2 * state->in_buf->allocated_len - 1);
  state->zs->next_in = (unsigned char *) state->in_buf->str + next_in_offset;

  int next_out_offset = (char *) state->zs->next_out - (char *) state->out_buf->str;
  state->out_buf->len = state->out_buf->allocated_len;
  g_string_set_size (state->out_buf, 2 * state->out_buf->allocated_len - 1);
  state->zs->next_out = (unsigned char *) state->out_buf->str + next_out_offset;
  state->zs->avail_out = state->out_buf->allocated_len - next_out_offset;
}

static gboolean
check_gzip_data (GzipChunksState *state)
{
  if (inflateReset (state->zs) != Z_OK) 
    die ("inflateReset failed: probably indicates a bug in %s", g_get_prgname ());

  state->crc = crc32 (0l, NULL, 0);

  int status = Z_OK;
  while (status != Z_STREAM_END)
    {
      refresh_in_buf (state->fin, state->zs, state->in_buf);
      state->zs->next_out = (unsigned char *) state->out_buf->str;
      state->zs->avail_out = state->out_buf->allocated_len;

      unsigned char *next_out_before = state->zs->next_out;

      status = Z_OK;
      status = inflate (state->zs, Z_NO_FLUSH);
      while (status == Z_BUF_ERROR && state->in_buf->allocated_len < MAX_BUF_SIZE)
        {
          expand_buffers (state);
          refresh_in_buf (state->fin, state->zs, state->in_buf);
          status = inflate (state->zs, Z_NO_FLUSH);
        }

      if (status == Z_BUF_ERROR)
        {
          info ("purported gzip chunk wants to expand buffers beyond %ld bytes, assuming corrupt data", state->in_buf->allocated_len);
          return FALSE;
        }
      else if (status == Z_DATA_ERROR)
        {
          info ("purported gzip chunk has bad data: %s", state->zs->msg);
          return FALSE;
        }
      else if (status == Z_NEED_DICT)
        die ("inflate returned Z_NEED_DICT: contingency unimplemented");
      else if (status != Z_OK && status != Z_STREAM_END)
        die ("inflate returned unexpected status %d: probably indicates a bug in %s", 
            status, g_get_prgname ());

      state->crc = crc32 (state->crc, next_out_before, state->zs->next_out - next_out_before);
    }

  return TRUE;
}

static gboolean
check_gzip_footer (GzipChunksState *state)
{
  unsigned long purported_crc = get_byte (state);
  purported_crc += ((unsigned) get_byte (state)) << 8;
  purported_crc += ((unsigned) get_byte (state)) << 16;
  purported_crc += ((unsigned) get_byte (state)) << 24;

  if (purported_crc != state->crc)
    {
      info ("purported crc %lu does not match computed crc %lu", purported_crc, state->crc);
      return FALSE;
    }

  unsigned long purported_uncompressed_bytes = get_byte (state);
  purported_uncompressed_bytes += ((unsigned) get_byte (state)) << 8;
  purported_uncompressed_bytes += ((unsigned) get_byte (state)) << 16;
  if (peek_byte (state) == EOF)
    {
      info ("purported gzip chunk ends in middle of 8 byte footer");
      return FALSE;
    }
  purported_uncompressed_bytes += ((unsigned) get_byte (state)) << 24;

  if (purported_uncompressed_bytes != state->zs->total_out)
    {
      info ("purported uncompressed size %lu bytes does not match actual uncompressed size %lu bytes", 
            purported_uncompressed_bytes, state->zs->total_out); 
      return FALSE;
    }

  return TRUE;
}

static off_t
get_offset (GzipChunksState *state)
{
  return ftello (state->fin) - state->zs->avail_in;
}

/* returns true if it reads a valid gzip chunk, false if not */
static gboolean
read_chunk (GzipChunksState *state)
{
  /* g_string_set_size (state->chunk_buf, 0); */
  off_t chunk_offset = get_offset (state);

  if (check_gzip_header (state) 
      && check_gzip_data (state)
      && check_gzip_footer (state))
    {
      state->good_chunk_offset = chunk_offset;
      return TRUE;
    }
  else if (state->bad_chunk_offset < 0)
    state->bad_chunk_offset = chunk_offset;

  return FALSE;
}

/* returns true if magic found, false if eof */
static gboolean
find_magic (GzipChunksState *state)
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

/* This function should be called after reading a good gzip chunk, or on eof.
 * If --invalid and we have an invalid chunk, write it. If not, write the valid
 * chunk.
 */
static void
maybe_write_chunk (GzipChunksState *state)
{
  off_t start_offset = -1;
  if (!options.invalid && state->good_chunk_offset >= 0)
    {
      info ("writing good chunk offset=%lld length=%lld", 
          (long long) state->good_chunk_offset, 
          (long long) (get_offset (state) - state->good_chunk_offset));
      start_offset = state->good_chunk_offset;
    }
  else if (options.invalid && state->bad_chunk_offset >= 0)
    {
      info ("writing bad chunk offset=%lld length=%lld", 
          (long long) state->bad_chunk_offset, 
          (long long) (get_offset (state) - state->bad_chunk_offset));
      start_offset = state->bad_chunk_offset;
    }
  else
    return;

  FILE *fout;
  if (state->split_dir)
    {
      GString *filename = g_string_new ("");

      if (options.invalid)
        g_string_printf (filename, "%s/bad-chunk-offset-%lld.dat",
            state->split_dir, (long long) start_offset);
      else
        g_string_printf (filename, "%s/good-chunk-offset-%lld.gz",
            state->split_dir, (long long) start_offset);

      errno = 0;
      fout = fopen (filename->str, "wb");
      if (fout == NULL) 
        die ("%s: %s", filename->str, g_strerror (errno));

      info ("writing %s", filename->str);

      g_string_free (filename, TRUE);
    }
  else
    fout = state->fout;

  off_t bytes_to_write = get_offset (state) - start_offset;

  errno = 0;
  if (fseeko (state->fin, start_offset, SEEK_SET) != 0)
    die ("fseeko: %s", g_strerror (errno));

  off_t bytes_written;
  for (bytes_written = 0; bytes_written < bytes_to_write; bytes_written++)
    { 
      int byte = fgetc (state->fin);
      g_assert (byte != EOF);
      byte = fputc (byte, fout);
      if (byte == EOF)
        /* shouldn't ever happen so don't worry too much about the error message, right? */
        die ("error writing"); 
    }

  if (state->split_dir)
    fclose (fout);

  /* seek back to end of buffered in */
  errno = 0;
  if (fseeko (state->fin, state->zs->avail_in, SEEK_CUR) != 0)
    die ("fseeko: %s", g_strerror (errno));

  state->dumped_chunks++;
  state->dumped_bytes += bytes_written;
}

int
main (int    argc,
      char **argv)
{
  setlocale (LC_ALL, "");

  GzipChunksState state;
  init_state (&state, &argc, &argv);

  if (options.start_offset)
    if (fseeko (state.fin, options.start_offset, SEEK_SET) != 0)
      die ("fseeko: %s", g_strerror (errno));

  while (peek_byte (&state) != EOF && 
      (options.end_offset < 0 || get_offset (&state) < options.end_offset))
    if (read_chunk (&state))
      {
        /* Only now do we know the bad chunk preceding this good chunk, if
         * any, is complete. Write out either the new good chunk or the
         * preceding bad chunk, depending if --invalid. */
        maybe_write_chunk (&state);
        state.bad_chunk_offset = -1;
        state.good_chunk_offset = -1;
      }
    else
      {
        state.good_chunk_offset = -1;
        find_magic (&state);
      }
  maybe_write_chunk (&state);

  FILE *report_out = state.fout == stdout ? stderr : stdout;
  fprintf (report_out, "%s: dumped %d %s gzip chunks totaling %lld bytes\n", 
      g_get_prgname (), state.dumped_chunks, 
      options.invalid ? "invalid" : "valid", (long long) state.dumped_bytes);

  free_state_stuff (&state);

  return 0;
}
