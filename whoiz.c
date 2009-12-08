/* $Id$
 *
 * vim: set sw=2 et:
 *
 * whoiz.c: Perform whois queries (RFC 3912).
 *
 * Copyright (C) 2009 Internet Archive
 * Copyright (C) 2009 Noah Levitt
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
#include <gio/gio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <locale.h>

static const int DEFAULT_PORT = 43;

/* North America-centric, but it should refer us to the right server e.g.
 * "ReferralServer: whois://whois.apnic.net" */
static const char *DEFAULT_IP_WHOIS_SERVER = "whois.arin.net";

/* Look up "com" "net" "fr" "info" etc */
static const char *ULTRA_SUFFIX_WHOIS_SERVER = "whois.iana.org";

/* If whois.iana.org doesn't know of a server for a particular country code,
 * look it up here instead */
static const char *FALLBACK_CCTLD_WHOIS_SERVER = "whois.cocca.cx";

/*
 * [whois://whois.arin.net/192.102.239.53] ReferralServer: whois://whois.apnic.net
 * [whois://whois.arin.net/208.49.199.10] ReferralServer: rwhois://rwhois.gblx.net:4321
 * [whois://whois.arin.net/195.154.120.129] ReferralServer: whois://whois.ripe.net:43
 * [whois://whois.iana.org/fr] Whois Server (port 43): whois.nic.fr
 * [whois://whois.verisign-grs.com/domain%201stbattalion9thmarinesfirebase.net]    Whois Server: whois.fastdomain.com
 * [server: whois.arin.net] [query: "206.51.225.143"] ReferralServer: rwhois://rwhois.noc4hosts.com:4321/
 */
static const char *REFERRAL_SERVER_PATTERN = "^\\s*(?:whois server|ReferralServer)[^:\r\n]*:.*?([a-zA-Z0-9.:-]+)/*$";

/* Break the connection after receiving more than this many bytes */
static const gsize MAX_SANE_RESPONSE_BYTES = 50000;

static char *minus_h_host = NULL;
static int minus_p_port = -1;

static GOptionEntry entries[] =
{
  { "host", 'h', 0, G_OPTION_ARG_STRING, &minus_h_host, "Query whois server HOST", "HOST" },
  { "port", 'p', 0, G_OPTION_ARG_INT, &minus_p_port, "Connect to server port PORT", "PORT" },
  { NULL }
};

/* do not free return value */
static GRegex *
referral_server_regex ()
{
  static GRegex *regex = NULL;

  if (regex == NULL)
    {
      GError *error = NULL;
      regex = g_regex_new (REFERRAL_SERVER_PATTERN, 
                           G_REGEX_CASELESS|G_REGEX_MULTILINE|G_REGEX_RAW, 
                           0, &error);
      if (regex == NULL || error != NULL)
        {
          g_printerr ("g_regex_new (%s): %s\n", REFERRAL_SERVER_PATTERN,
                      error->message);
          exit (6);
        }
    }

  return regex;
}

/* return value must be freed */
static GSocketConnection *
open_connection (char *server_colon_port,
                 int   default_port)
{
  GSocketClient *client = g_socket_client_new ();
  GSocketConnection *connection;
  GError *error = NULL;

  connection = g_socket_client_connect_to_host (client, server_colon_port, default_port, NULL, &error);
  if (connection == NULL) 
    {
      g_printerr ("g_socket_client_connect_to_host (%s): %s\n", server_colon_port, error->message);
      exit (3);
    }

  g_object_unref (client);
  return connection;
}

static void 
send_query (GSocket *socket,
            char    *query)
{
  g_assert (g_socket_is_connected (socket));

  GError *error = NULL;
  gint bytes_left = strlen (query);

  while (bytes_left > 0)
    {
      gssize bytes_sent = g_socket_send (socket, query, bytes_left, NULL, &error);
      if (bytes_sent == -1) 
        {
          g_printerr ("g_socket_send: %s\n", error->message);
          exit (4);
        }

      bytes_left -= bytes_sent;
    }
}

/* return value must be freed */
static char *
get_response (GSocket *socket)
{
  g_assert (g_socket_is_connected (socket));

  GString *response = g_string_new ("");
  static char buf[4096];
  GError *error = NULL;
  gssize bytes_received;

  do 
    {
      bytes_received = g_socket_receive (socket, buf, sizeof (buf), NULL, &error);

      if (bytes_received > 0)
        g_string_append_len (response, buf, bytes_received);
      else if (bytes_received < 0)
        {
          g_printerr ("g_socket_receive: %s\n", error->message);
          exit (5);
        }

      if (response->len > MAX_SANE_RESPONSE_BYTES)
        g_printerr ("whoiz: warning: Truncating response after %ld bytes", response->len);
    }
  while (bytes_received > 0 && response->len <= MAX_SANE_RESPONSE_BYTES);

  return g_string_free (response, FALSE);
}

/* returns whois response which must be freed */
static char *
simple_lookup (char *server_colon_port,
               char *query)
{
  GSocketConnection *connection = open_connection (server_colon_port, DEFAULT_PORT);
  GSocket *socket = g_socket_connection_get_socket (connection);

  GString *query_plus_crlf = g_string_new (query);
  g_string_append (query_plus_crlf, "\r\n");

  /* the transaction */
  send_query (socket, query_plus_crlf->str);
  char *response = get_response (socket);

  g_string_free (query_plus_crlf, TRUE);
  g_object_unref (connection);

  /* it seems that the connection owns this object (doc is unclear) */
  /* g_object_unref (socket); */

  return response;
}

/* return value must be freed */
static char *
domain_query_special_syntax (const char *server_colon_port,
                             const char *domain)
{
  GString *special_query = g_string_new (domain);

  if (g_strcmp0 (server_colon_port, "whois.verisign-grs.com") == 0 || 
      g_strcmp0 (server_colon_port, "whois.verisign-grs.com:43") == 0)
    g_string_printf (special_query, "domain %s", domain);
  else if (g_strcmp0 (server_colon_port, "whois.denic.de") == 0 || 
           g_strcmp0 (server_colon_port, "whois.denic.de:43") == 0)
    g_string_printf (special_query, "-T dn %s", domain);

  return g_string_free (special_query, FALSE);
}

/* Assumes query is either an ip address or domain name. If not, user should
 * specify server on the command line with -h. */
static void
smart_lookup (char *query)
{
  char *next_server;
  char *next_query;

  if (g_hostname_is_ip_address (query))
    {
      next_server = g_strdup (DEFAULT_IP_WHOIS_SERVER);
      next_query = g_strdup (query);
    }
  else
    {
      next_server = g_strdup (ULTRA_SUFFIX_WHOIS_SERVER);
      char *last_dot = strrchr (query, '.');
      if (last_dot != NULL)
        next_query = g_strdup (last_dot + 1);
      else
        next_query = g_strdup (query);
    }

  while (next_server != NULL)
    {
      g_print ("======== [server: %s] [query: \"%s\"] ========\n", next_server, next_query);
      char *response = simple_lookup (next_server, next_query);
      puts (response);

      gboolean is_cctld = (strlen (next_query) == 2);
      g_free (next_server);
      g_free (next_query);
      next_server = NULL;

      /* look for referral server in the response */
      GMatchInfo *match_info;
      if (g_regex_match (referral_server_regex (), response, 0, &match_info))
        {
          next_server = g_match_info_fetch (match_info, 1);
          next_query = domain_query_special_syntax (next_server, query);
        }
      else if (is_cctld)
        {
          /* use fallback for country code without its own whois server */
          next_server = g_strdup (FALLBACK_CCTLD_WHOIS_SERVER);
          next_query = domain_query_special_syntax (next_server, query);
        }

      g_match_info_free (match_info);
      g_free (response);
    }
}

/* If it's a whois url, returns TRUE and populates *server and *query, which
 * must be freed. Otherwise returns FALSE. */
static gboolean
parse_whois_url (char  *url,
                 char **server,
                 char **query)
{
  char *whois_url_pattern = "whois://([^/]*)/(.*)$";
  GError *error = NULL;
  gboolean is_whois_url = FALSE;

  GRegex *whois_url_regex = g_regex_new (whois_url_pattern, G_REGEX_CASELESS|G_REGEX_RAW, 0, &error);
  GMatchInfo *match_info;
  if (whois_url_regex == NULL || error != NULL)
    {
      g_printerr ("g_regex_new (%s): %s\n", whois_url_pattern, error->message);
      exit (7);
    }

  if (g_regex_match (whois_url_regex, url, 0, &match_info))
    {
      is_whois_url = TRUE;

      char *s = g_match_info_fetch (match_info, 1);
      if (strlen (s) > 0)
        *server = s;
      else
        g_free (s);

      char *escaped_query = g_match_info_fetch (match_info, 2);
      *query = g_uri_unescape_string (escaped_query, NULL);
      g_free (escaped_query);
    }

  g_match_info_free (match_info);
  g_regex_unref (whois_url_regex);

  return is_whois_url;
}

/* Fills in *server and *query, which must be freed by the caller */
static void
parse_command_line (int    argc,
                    char **argv,
                    char **server,
                    char **query)
{
  GOptionContext *context = g_option_context_new ("{ QUERY | WHOIS_URL }");
  GError *error = NULL;
  int i;

  *server = NULL;
  *query = NULL;

  g_option_context_set_summary (context, "Perform whois queries (RFC 3912).");
  g_option_context_add_main_entries (context, entries, NULL);
  g_option_context_set_description (context, 
      "Examples of usage:\n"
      "  whoiz archive.org\n"
      "  whoiz whois://whois.pir.org/archive.org\n"
      "  whoiz whois:///192.168.1.1\n"
      "  whoiz -h whois.ripe.net -- -q sources\n"
      "  whoiz whois://whois.ripe.net:43/-q\%20sources\n");

  if (!g_option_context_parse (context, &argc, &argv, &error))
    {
      g_printerr ("g_option_context_parse: %s\n", error->message);
      exit (1);
    }

  if (argc < 2)
    {
      g_printerr ("whoiz: error: Nothing to look up, whois query or url not specified\n\n");
      g_printerr ("%s", g_option_context_get_help (context, TRUE, NULL));
      exit (2);
    }

  /* concatenate remaining args into a query */
  i = 1;
  if (g_strcmp0 (argv[i], "--") == 0)
    i++;
  GString *query_or_url = g_string_new (argv[i]);
  for (i++; i < argc; i++)
    {
      g_string_append_c (query_or_url, ' ');
      g_string_append (query_or_url, argv[i]);
    }

  if (parse_whois_url (query_or_url->str, server, query))
    {
      if (minus_h_host != NULL)
        {
          g_printerr ("whoiz: warning: You specified a whois url to look up, so"
                      " the host you specified with --host will be ignored.\n");
          g_free (minus_h_host);
        }
      g_string_free (query_or_url, TRUE);
    }
  else
    {
      /* not a whois:// url, just a query string */
      *query = g_string_free (query_or_url, FALSE);
      if (minus_h_host != NULL)
        *server = minus_h_host;
    }

  g_option_context_free (context);
}

int
main (int    argc,
      char **argv)
{
  setlocale (LC_ALL, "");
  g_type_init ();

  char *server;
  char *query;

  parse_command_line (argc, argv, &server, &query);

  if (server != NULL)
    {
      g_printerr ("======== [server: %s] [query: \"%s\"] ========\n", server, query);
      char *response = simple_lookup (server, query);
      puts (response);

      g_free (response);
      g_free (server);
    }
  else
    smart_lookup (query);

  g_free (query);

  exit (0);
}
