#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netdb.h>
#include <fcntl.h>
#include <polarssl/ssl.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/certs.h>
#include <polarssl/x509.h>
#include <polarssl/ssl_cache.h>
#include <polarssl/net.h>
#include <polarssl/dhm.h>
#include "mmap.h"

#ifdef POLARSSL_ERR_NET_TRY_AGAIN
#error polarssl version too old, try the svn trunk
#endif

static int library_inited;

const char* ssl_server_cert="server.pem";
const char* ssl_client_crl="clientcrl.pem";
const char* ssl_client_ca="clientca.pem";
const char* ssl_ciphers="DEFAULT";
const char* ssl_client_cert="clientcert.pem";
const char* ssl_dhparams="dhparams.pem";

const unsigned char ssl_default_dhparams[]="-----BEGIN DH PARAMETERS-----\n"
"MIIBCAKCAQEAhS4NySChob9OZmB7WOUbOIxurRRbItWnKmC2fq1pJHRft/r72/qq\n"
"g8qquhYAmikXgX4+uZEgfLBWPlx1d8wHggnKtEJ+0KzlGpxek7QORwN2j9872jXC\n"
"25iZar+Om4hUXREuVyGU02GmGHgfemVT1mOvZMbBxzTfmaUdP9Q304oKz4RUYV1w\n"
"+Jv3iO6MYySz6bhsc7lSyayUIJxXJoaqgz6EJVImU6LwXo8gUbD5GUVXhEzDHuRG\n"
"fbKleVvLf1MC7TT6H5PAFFOkfFET//C9QJkSmUsg3u5GtwvKNZhwrggqNzchXSkS\n"
"FDQXPlpTK7h3BlR8vDadEpT68OcdLr2+owIBAg==\n"
"-----END DH PARAMETERS-----\n";

x509_crt srvcert;
pk_context key;
entropy_context entropy;
ctr_drbg_context ctr_drbg;
ssl_cache_context cache;

int ciphersuites[] =
{
  TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
  TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
  TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
  TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
  TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
  TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
  TLS_RSA_WITH_AES_256_GCM_SHA384,
  TLS_RSA_WITH_AES_256_CBC_SHA256,
  TLS_RSA_WITH_AES_256_CBC_SHA,
  TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
  TLS_RSA_WITH_AES_128_GCM_SHA256,
  TLS_RSA_WITH_AES_128_CBC_SHA256,
  TLS_RSA_WITH_AES_128_CBC_SHA,
  TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
  TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
  TLS_RSA_WITH_3DES_EDE_CBC_SHA,
  TLS_RSA_WITH_RC4_128_SHA,
//  TLS_RSA_WITH_RC4_128_MD5,
  0
};

int my_net_recv( void *ctx, unsigned char *buf, size_t len ) {
  int sock=(int)(uintptr_t)ctx;
  return net_recv(&sock, buf, len);
}

int my_net_send( void *ctx, const unsigned char *buf, size_t len ) {
  int sock=(int)(uintptr_t)ctx;
  return net_send(&sock, buf, len);
}

int init_serverside_tls(ssl_context* ssl,int sock) {
  size_t l,i;
  int found=0;
  char* buf;
  if (!library_inited) {
    library_inited=1;
    ssl_cache_init(&cache);
    entropy_init(&entropy);
    if (ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (const unsigned char*) "gatling", strlen("gatling")))
      return -1;
    memset(&key,0,sizeof(key));
  } else {
    x509_crt_free(&srvcert);
    pk_free(&key);
  }

  memset(&srvcert,0,sizeof(x509_crt));
  /* for compatibility we expect the same file format as openssl, which
   * looks like this:

   -----BEGIN RSA PRIVATE KEY-----
   [base64]
   -----END RSA PRIVATE KEY-----
   -----BEGIN CERTIFICATE-----
   [base64]
   -----END CERTIFICATE-----

   */
  buf=(char*)mmap_read(ssl_server_cert,&l);
  if (!buf) return -1;
  for (i=0; i<l-sizeof("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"); ++i)
    if (!memcmp(buf+i,"-----BEGIN CERTIFICATE-----",sizeof("-----BEGIN CERTIFICATE-----")-1)) {
      found=1;
      break;
    }
  if (!found) {
fail:
    mmap_unmap(buf,l);
    return -1;
  }
  pk_init(&key);
  /* parse cert and key */
  if (x509_crt_parse(&srvcert,(unsigned char*)buf+i,l-i) ||
      pk_parse_key(&key,(unsigned char*)buf,i,NULL,0))
    goto fail;
  mmap_unmap(buf,l);

  memset(ssl,0,sizeof(*ssl));

  if (ssl_init(ssl))
    return -1;

  ssl_set_endpoint( ssl, SSL_IS_SERVER );
  ssl_set_authmode( ssl, SSL_VERIFY_NONE );
  ssl_set_rng( ssl, ctr_drbg_random, &ctr_drbg );
  ssl_set_session_cache( ssl, ssl_cache_get, &cache, ssl_cache_set, &cache);
  ssl_set_ca_chain( ssl, srvcert.next, NULL, NULL);
  ssl_set_own_cert( ssl, &srvcert, &key );

  ssl_session_reset( ssl );
  ssl_set_bio( ssl, my_net_recv, (char*)(uintptr_t)sock, my_net_send, (char*)(uintptr_t)sock );

  ssl_set_ciphersuites( ssl, ciphersuites );

  {
    dhm_context dhm;
    memset(&dhm,0,sizeof(dhm));
    if (dhm_parse_dhmfile(&dhm, ssl_dhparams) && dhm_parse_dhmfile(&dhm, ssl_server_cert))
      dhm_parse_dhm(&dhm, ssl_default_dhparams, sizeof(ssl_default_dhparams)-1);
    ssl_set_dh_param_ctx(ssl, &dhm);
  }
//  ssl_set_dh_param( ssl, "CD95C1B9959B0A135B9D306D53A87518E8ED3EA8CBE6E3A338D9DD3167889FC809FE1AD59B38C98D1A8FCE47E46DF5FB56B8EA3B03B2132C249A99209F62A1AD63511BD08A60655B0463B6F1BB79BEC9D17C71BD269C6B50CF0EDDAAB83290B4C697A7F641FBD21EE0E7B57C698AFEED8DA3AB800525E6887215A61CA62DC437", "04" );

  return 0;
}

