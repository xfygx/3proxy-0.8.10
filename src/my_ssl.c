
#define _CRT_SECURE_NO_WARNINGS

#include "structures.h"
#include <memory.h>
#include <fcntl.h>
#ifndef _WIN32
#include <sys/file.h>
#endif

#include <assert.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "proxy.h"
#include "my_ssl.h"


typedef struct _ssl_conn {
	SSL_CTX *ctx;
	SSL *ssl;
} ssl_conn;

static X509 *CA_cert = NULL;
static EVP_PKEY *CA_key = NULL;
static EVP_PKEY *server_key = NULL;
static X509_NAME *name = NULL;

pthread_mutex_t ssl_file_mutex;


static char errbuf[256];

static char hexMap[] = { 
                          '0', '1', '2', '3', '4', '5', '6', '7', 
                          '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
                        }; 

static BIO *bio_err=NULL;


static size_t bin2hex (const unsigned char* bin, size_t bin_length, char* str, size_t str_length) 
{
	char *p;
	size_t i;
	
	if ( str_length < ( bin_length+1) ) 
		return 0; 

	p = str; 
	for ( i=0; i < bin_length; ++i )  
	{ 
		*p++ = hexMap[*bin >> 4];  
		*p++ = hexMap[*bin & 0xf]; 
		++bin;
	} 
	
	*p = 0; 

	return p - str; 
}

static int add_ext(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return 0;

	X509_add_ext(cert,ex,-1);
	X509_EXTENSION_free(ex);
	return 1;
}

extern char *cert_path;

void del_ext(X509 *dst_cert, int nid, int where){
	int ex;

	ex = X509_get_ext_by_NID(dst_cert, nid, where);
	if(ex>=0){
		X509_EXTENSION *ext;
		if((ext = X509_delete_ext(dst_cert, ex))) X509_EXTENSION_free(ext);
	}

}

SSL_CERT ssl_copy_cert(SSL_CERT cert)
{
	int err = -1;
	FILE *fcache;
	X509 *src_cert = (X509 *) cert;
	X509 *dst_cert = NULL;

	EVP_PKEY *pk = NULL;
	RSA *rsa = NULL;

	char* pem_string = NULL;
	size_t cert_len = 0;
	BIO* certBio = NULL;

	static char hash_name_sha1[sizeof(src_cert->sha1_hash)*2 + 1];
	static char cache_name[200];

	bin2hex(src_cert->sha1_hash, sizeof(src_cert->sha1_hash), hash_name_sha1, sizeof(hash_name_sha1));
	sprintf(cache_name, "%s%s.pem", cert_path, hash_name_sha1);
	/* check if certificate is already cached */
	fcache = fopen(cache_name, "rb");
	if ( fcache != NULL ) {
#ifndef _WIN32
		flock(fileno(fcache), LOCK_SH);
#endif

		fseek(fcache, 0, SEEK_END);
		cert_len = ftell(fcache);
		fseek(fcache, 0, SEEK_SET);
		pem_string = (char *)malloc(cert_len);
		fread(pem_string, cert_len, 1, fcache);
		
		certBio = BIO_new(BIO_s_mem());
		BIO_write(certBio, pem_string, cert_len);
		dst_cert = PEM_read_bio_X509(certBio, NULL, 0, NULL);
		
		free(pem_string);
		BIO_free(certBio);

		//dst_cert = PEM_read_X509(fcache, &dst_cert, NULL, NULL);
#ifndef _WIN32
		flock(fileno(fcache), LOCK_UN);
#endif
		fclose(fcache);
		if ( dst_cert != NULL ){
			return dst_cert;
		}
	}

	/* proceed if certificate is not cached */
	dst_cert = X509_dup(src_cert);
	if ( dst_cert == NULL ) {
		return NULL;
	}
	del_ext(dst_cert, NID_crl_distribution_points, -1);
	del_ext(dst_cert, NID_info_access, -1);
	del_ext(dst_cert, NID_authority_key_identifier, -1);
	del_ext(dst_cert, NID_certificate_policies, 0);

	err = X509_set_pubkey(dst_cert, server_key);
	if ( err == 0 ) {
		X509_free(dst_cert);
		return NULL;
	}


	/* Its self signed so set the issuer name to be the same as the
 	 * subject.
	 */
	err = X509_set_issuer_name(dst_cert, name);
	if(!err){
		X509_free(dst_cert);
		return NULL;
	}
	err = X509_digest(dst_cert, EVP_sha1(), dst_cert->sha1_hash, NULL);
	if(!err){
		X509_free(dst_cert);
		return NULL;
	}
	err = X509_sign(dst_cert, CA_key, EVP_sha256());
	if(!err){
		X509_free(dst_cert);
		return NULL;
	}

	/* write to cache */

	//fcache = fopen(cache_name, "wb");
	BIO * f = BIO_new_file(cache_name, "w");
	if ( f != NULL ) {
#ifndef _WIN32
		//flock(fileno(fcache), LOCK_EX);
#endif
		PEM_write_bio_X509(f, dst_cert);

		//PEM_write_X509(fcache, dst_cert);
#ifndef _WIN32
		//flock(fileno(fcache), LOCK_UN);
#endif
		//fclose(fcache);
		BIO_free_all(f);
	}
	return dst_cert;
}


SSL_CONN ssl_handshake_to_server(SOCKET s, char * hostname, SSL_CERT *server_cert, char **errSSL)
{
	int err = 0;
	X509 *cert;
	ssl_conn *conn;

	*errSSL = NULL;

	conn = (ssl_conn *)malloc(sizeof(ssl_conn));
	if ( conn == NULL ){
		return NULL;
	}

	conn->ctx = SSL_CTX_new(SSLv23_client_method());
	if ( conn->ctx == NULL ) {
		free(conn);
		return NULL;
	}

	conn->ssl = SSL_new(conn->ctx);
	if ( conn->ssl == NULL ) {
		SSL_CTX_free(conn->ctx);
		free(conn);
		return NULL;
	}

	if(!SSL_set_fd(conn->ssl, s)){
		ssl_conn_free(conn);
		return NULL;
	}
	if(hostname && *hostname)SSL_set_tlsext_host_name(conn->ssl, hostname);
	err = SSL_connect(conn->ssl);
	if ( err == -1 ) {
		*errSSL = ERR_error_string(ERR_get_error(), errbuf);
		ssl_conn_free(conn);
		return NULL;
	}

	cert = SSL_get_peer_certificate(conn->ssl);     
	if(!cert) {
		ssl_conn_free(conn);
		return NULL;
	}

	/* TODO: Verify certificate */

	*server_cert = cert;

	return conn;
}

SSL_CONN ssl_handshake_to_client(SOCKET s, SSL_CERT server_cert, char** errSSL)
{
	int err = 0;
	X509 *cert;
	ssl_conn *conn;

	*errSSL = NULL;

	conn = (ssl_conn *)malloc(sizeof(ssl_conn));
	if ( conn == NULL )
		return NULL;

	conn->ctx = SSL_CTX_new(SSLv23_server_method());
	if ( conn->ctx == NULL ) {
		free(conn);
		return NULL;
	}

	err = SSL_CTX_use_certificate(conn->ctx, (X509 *) server_cert);
	if ( err <= 0 ) {
		SSL_CTX_free(conn->ctx);
		free(conn);
		return NULL;
	}

	err = SSL_CTX_use_PrivateKey(conn->ctx, server_key);
	if ( err <= 0 ) {
		SSL_CTX_free(conn->ctx);
		free(conn);
		return NULL;
	}
/*
	err = SSL_CTX_load_verify_locations(conn->ctx, "3proxy.pem",
                                   NULL);
	if ( err <= 0 ) {
		SSL_CTX_free(conn->ctx);
		free(conn);
		return NULL;
	}
*/

	conn->ssl = SSL_new(conn->ctx);
	if ( conn->ssl == NULL ) {
		SSL_CTX_free(conn->ctx);
		free(conn);
		return NULL;
	}

	SSL_set_fd(conn->ssl, (int)s);
	err = SSL_accept(conn->ssl);
	if ( err <= 0 ) {
		*errSSL = ERR_error_string(ERR_get_error(), errbuf);
		ssl_conn_free(conn);
		return NULL;
	}

	//
	// client certificate
	// TODO: is it required?
	//
	cert = SSL_get_peer_certificate(conn->ssl);     

	if ( cert != NULL )
		X509_free(cert);

	return conn;
}

int ssl_read(SSL_CONN connection, void * buf, int bufsize)
{
	ssl_conn *conn = (ssl_conn *) connection;

	return SSL_read(conn->ssl, buf, bufsize);
}

int ssl_write(SSL_CONN connection, void * buf, int bufsize)
{
	ssl_conn *conn = (ssl_conn *) connection;

	return SSL_write(conn->ssl, buf, bufsize);
}
int ssl_pending(SSL_CONN connection)
{
	ssl_conn *conn = (ssl_conn *) connection;

	return SSL_pending(conn->ssl);
}

void ssl_conn_free(SSL_CONN connection)
{
	ssl_conn *conn = (ssl_conn *) connection;

	if(conn){
		if(conn->ssl){
			SSL_shutdown(conn->ssl);
			SSL_free(conn->ssl);
		}
		if(conn->ctx) SSL_CTX_free(conn->ctx);
		free(conn);
	}
}

void _ssl_cert_free(SSL_CERT cert)
{
	X509_free((X509 *)cert);
}


 
/* This array will store all of the mutexes available to OpenSSL. */ 
static pthread_mutex_t *mutex_buf= NULL;
 
 
static void locking_function(int mode, int n, const char * file, int line)
{
  if (mode & CRYPTO_LOCK)
    pthread_mutex_lock(mutex_buf + n);
  else
    pthread_mutex_unlock(mutex_buf + n);
}
 
static unsigned long id_function(void)
{
#ifdef _WIN32
  return ((unsigned long)GetCurrentThreadId());
#else
  return ((unsigned long)pthread_self());
#endif
}
 
int thread_setup(void)
{
  int i;
 
  mutex_buf = malloc(CRYPTO_num_locks(  ) * sizeof(pthread_mutex_t));
  if (!mutex_buf)
    return 0;
  for (i = 0;  i < CRYPTO_num_locks(  );  i++)
    pthread_mutex_init(mutex_buf +i, NULL);
  CRYPTO_set_id_callback(id_function);
  CRYPTO_set_locking_callback(locking_function);
  return 1;
}
 
int thread_cleanup(void)
{
  int i;
 
  if (!mutex_buf)
    return 0;
  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for (i = 0;  i < CRYPTO_num_locks(  );  i++)
    pthread_mutex_destroy(mutex_buf +i);
  free(mutex_buf);
  mutex_buf = NULL;
  return 1;
}



int ssl_file_init = 0;


void ssl_init(void)
{

	if(!ssl_file_init++)pthread_mutex_init(&ssl_file_mutex, NULL);

	pthread_mutex_lock(&ssl_file_mutex);
	thread_setup();

	SSLeay_add_ssl_algorithms();
	SSL_load_error_strings();

	size_t cert_len = 0;
	
const char* proxyCert = "-----BEGIN CERTIFICATE-----\n\
MIIDKjCCAhICCQCRhOk1HLonjzANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJJ\n\
TjELMAkGA1UECAwCTE4xCzAJBgNVBAcMAkxOMQ4wDAYDVQQKDAVlbmR1YzEOMAwG\n\
A1UECwwFZW5kdWMxDjAMBgNVBAMMBWVuZHVjMB4XDTE3MTAyODA1MDAzOFoXDTIw\n\
MDcyNDA1MDAzOFowVzELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAkxOMQswCQYDVQQH\n\
DAJMTjEOMAwGA1UECgwFZW5kdWMxDjAMBgNVBAsMBWVuZHVjMQ4wDAYDVQQDDAVl\n\
bmR1YzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMoxEZxJY3x8s5zv\n\
b/txDwKt3HT9YrvI5mMzOhjl7IZJCBX7bSZzPD4kKAuV7bjuumxG/s2T+DvNcYpX\n\
rAJ8oMfRBaRs6Z1Xc/zcYBK59Tw1hihERt2kRDTv0/BQtsSqUh1pa7wG/Eqf6VPt\n\
epSY1EmQp8XT9D7fHcmMavie/CjAPL8zWKcuXRF3EznYggzFH7YHr+SFRUGkVkjQ\n\
du50TAkafYuNLXDlk9y5rHwu5Q0a3zxzDDYCyTNNyK1zkK8KQYdu4ysVNM6XSfmj\n\
Sca6xzGh7O27qG0p6AyDnYgS/xnbGLfG22JBDkyaz//8526lR7F6qXz0X7x63Qbs\n\
HvmpPtkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAnhjYbkfmxJRLWYwZMeLjVGdt\n\
+uUecPuo4pDzX3dmFBhm4QBZgRjYEvhLxJ2fdvSwqfaWORiSoKiB/1MlQrsyfXzw\n\
3FS0QIu2a3ql2r9xRfrL6FWM2qqlU9D8Taw820A88BHGcqcooBCTRFJQD1hkwaln\n\
T9Bso6CErRhSgVlpItYiKTY6+HQbqS3cDKA8+bqBPSPBGnsAUX0ahC2ct0/Zdh6X\n\
TV6+hQD+wL8WnQB9OJWeNnX8NxBOXpv8e4zhDcvKwRf4lWR0+oWzeHnGkEoF+IwA\n\
yjXpKqDurfzNDsZoVgQ3/92m+0ApOabAIYoU+EVhVsMC8pSmvhmPWrNqGFuJjg==\n\
-----END CERTIFICATE-----\n";

	cert_len = strlen(proxyCert);
	
	BIO* certBio = BIO_new(BIO_s_mem());
	BIO_write(certBio, proxyCert, cert_len);
	CA_cert = PEM_read_bio_X509(certBio, NULL, 0, NULL);
	printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
	BIO_free(certBio);
	/* SHOW name */
	name = X509_get_subject_name(CA_cert);
	printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
	for (int i = 0; i < X509_NAME_entry_count(name); i++) {
		X509_NAME_ENTRY *e = X509_NAME_get_entry(name, i);
		ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
		char *str = ASN1_STRING_data(d);
		printf("%s\n", str);
	}

	const char* proxyCertPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEpgIBAAKCAQEAyjERnEljfHyznO9v+3EPAq3cdP1iu8jmYzM6GOXshkkIFftt\n\
JnM8PiQoC5XtuO66bEb+zZP4O81xilesAnygx9EFpGzpnVdz/NxgErn1PDWGKERG\n\
3aRENO/T8FC2xKpSHWlrvAb8Sp/pU+16lJjUSZCnxdP0Pt8dyYxq+J78KMA8vzNY\n\
py5dEXcTOdiCDMUftgev5IVFQaRWSNB27nRMCRp9i40tcOWT3LmsfC7lDRrfPHMM\n\
NgLJM03IrXOQrwpBh27jKxU0zpdJ+aNJxrrHMaHs7buobSnoDIOdiBL/GdsYt8bb\n\
YkEOTJrP//znbqVHsXqpfPRfvHrdBuwe+ak+2QIDAQABAoIBAQC8fZIVSLVeUEKB\n\
gxW6KmP782kaBz4MIfXldNQscexWI69ODt5qgfMfW0WZx2Oei69vUaAotlEsLxIy\n\
DhllGBorLUk9R+thqy2OBUPrMUDVqHAxCbWm2oRbdVj3J8e6/60djjHJUBnS19EF\n\
VNZ5wR/mlNxTKI0CL63tPuJadJxOv35OHvXX6O8PNlfvCb1QsvsgtwZ9bg/HCPq9\n\
a+i0Itn5EZHoB5DLQ11DQfp6jJ955H/BiCkPNG8U+Lc5sUL94RxASdbHkJ7jsTwK\n\
sPahzbWrmTZresjYXCJt0HjR1pL2wf19Giv/n97J5J8vcoWhsHPaebW9PjIcNA5k\n\
1RDtPruhAoGBAPalx/uM33d3zK5zQ+r6YzGUXe65Hn8mQ0TWSVXGVdTtvoYowChw\n\
kSJ4eCrNbyZWdgSiqDQJF4Qi9cQ98/UQvmXDugrBIb9zqJLiPnZODp86NQ3cE+AX\n\
uVv56LuPdM/cQ/NBQddlze0/ZbvToh98SXMlgHo17646HpiWT2CZ0/1LAoGBANHb\n\
wI639nBxldlORDjVgdOAFTFYgG3buDchtt8Nlse1X5uQr1mYsu+89KcBjLeuJYAr\n\
V0lg663gz9ZeGVliaR0GJzCAT+Hg0J1MGffUgHr+GcOponfWLElkJkTQoT+TladT\n\
wn0Od8L79pdS7h4+5S0Y18H4Qs+AH0gfnGr24VHrAoGBAL4wEWf4NayilRMD0KBV\n\
mL13YYMd/dUfxQlEj2HzwOWiuaIrtBi6zD8fU9H1fTq7ut9SKY+OXzLF3msHNqGG\n\
2roP1dpLGGHPpnI0wONqxz2inZxlUnIe+RBiQUK3mORbPY5KiKG2X7cMhr7xrvbG\n\
WMDQbyRNiNb4+/S/GtArbdrHAoGBAK2yWbrHAS8olIL8iPMRpRdN2Dyzp/lF9z+K\n\
pDYSpU4/DRdRthFOlixgFY91dOdDOL7RILoXgnq0rNIdqJWXIrFnOmCmk3e+AG1x\n\
Y70BIiaq0uBkM5lEp/tG7XXfyNc6bI/GgB/KLc4xhnTRq01VeZLOESb3OTVOMpYb\n\
s/fEx9JpAoGBANhp2HA94U1b7L4vHXO3htYO38WFhOrL54BhVO/w/N8hg6L8uot9\n\
sPPGIeQWVtv+u2jQ7Y9mhCM01AWrqvL4M5pOvSSPVpbEdvv8uP/vrvNxH/VgVmYO\n\
86AkpYBkiW1qopgCi0Kw6TLqdljVkm6T+b4+E0+zzZVEJvbYyI5e0xxy\n\
-----END RSA PRIVATE KEY-----";

	cert_len = strlen(proxyCertPrivateKey);

	certBio = BIO_new(BIO_s_mem());
	BIO_write(certBio, proxyCertPrivateKey, cert_len);
	CA_key = PEM_read_bio_PrivateKey(certBio, NULL, 0, NULL);
	printf("%s\n", ERR_error_string(ERR_get_error(), NULL));	
	BIO_free(certBio);

	const char* proxyServerPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEowIBAAKCAQEAojHfhPo0imr1JngCajXaKX8diK0up4ubhNCHvN5xZG7k2iv+\n\
6BkoKOdIMfWwTeLnq3NpDh52Q0acVlFEnHuxb0BUnbUG/3aqspthSZhdyWLhh0pq\n\
xC1y3e4KlExBGpSeeoIXwrNrzu3/ZjxJ2c/4GnyXlVHw2hAj4RDu6XRqHYFyZJh8\n\
hJdU12DLG0/dsN7WUDL+JD1tDkqSR4xGXjtBnJAXDM5RAhIYSKN8Rf/FzLY4u01d\n\
xyj59Ec3+sbrXXs98hZKt1z0HPXYES13uilzafZffyeVOYOPZp4s1jq+cGSw8oRi\n\
iq8BdXn2669BTGg5Kv9yymBanGj+qXsndtXNYwIDAQABAoIBAH0WN4sHp+Okb2J2\n\
pW4iEBl2tmFFJrkCWzNH25dWel75gzebPKDlXeqFzFDzaT/4IbFBdaD070IdP872\n\
KBMC9imVlGx4Q2hbrXPHj3VBs/rvbn13b/XSE0eDINeUI5WLTtmuYQLAewGA3TqM\n\
fmwkDvTmZ8U6B6U1U2ZtN8QGCxyrESAN7ZUnT5R72uDhxdYEMb9Jm6bZltUf310S\n\
PBLwkV0AIPrlxHJ+kp7V2g5GV9zA+ebFpzbTnqzic7NlTVsmeBSX49yb5qCHkOtb\n\
8Jopt5tGk0VYY4KjngNcS1yxWFJa0YK7vw5Ov1b9sx/RE07W1wVV84w8CqIvu60Y\n\
HCJPm9ECgYEAz8J556EejuhhlcSq3FWwZqWYM/upp8IYFIGuQ63rzBf1zSEEQpUE\n\
NpDbM4aSQVc72NFsKmWVtKhFwf0OeZ+XAb0nzynZJuQkW8o2uE7pSHmNMij+4VWZ\n\
wluaAUnCw5EfnO9speDKCKeC6IiMbmeRTXbqOcUaFnlE2qRpKEwVBrsCgYEAx9r1\n\
Y8xYdbmyHgfa8uwI9iUHYN7CP6oO4cV5ZMbJG8nqJguqIUQ1w0zwYRRQqVThayyi\n\
LVN4WQMqVmbInO8Jvs/4oCEw5tVccPj2soCwbKMePNx1g5m5xXiSD/CCRFOCwA6Y\n\
Ed3goL7yeMenpxO7AhwvEer78rtFf9vxkcqYbXkCgYEAnYasXbcpb1u9Ggy7LEMA\n\
dGPcapXHhj5BedL16bUGU4JbSgRdsYpBXooo2gGQBWD6LKRlaiQKBaeM9NBF2Gvr\n\
2FKuy4HEd5uGAd7p7IdQlDYtm7m/v+Tip55Cv/VIanYvzRMwgvlU1okEVgGq0M9Q\n\
ObcPU2wiIqYiUdFVNkuxqZ8CgYAKqssyOnP2RKUXKUAseyC3Up6kMv+XOlJ1Bn9G\n\
O738N7jBsxmvkN51wCOMavMrNpaZi9ZUKQJhbePSnMXUaoXQo3UXxu2/RGAcv40b\n\
VfcUtVgl03aKQahCu/6/zwyE7RgrfBvtyDP3IHn8rFtsdYcjw7FXeX1dJVW+T1UD\n\
fRbJsQKBgGd8cNKgmiX/MBcot1ADRYpDJxnKyu0/Q19oy6bxtIhyCYpVGncG2EVW\n\
avpkxzG57djYtVT/kYygQKOwvKXFlmqB18RkfKsUK0Jb1Gyqj24vKteVJmNUAME5\n\
2z/n6XV7IPc7w9et5R0ghKgOmSqmRQesJwTq/cAe1fW1J7IDAPzy\n\
-----END RSA PRIVATE KEY-----";


	cert_len = strlen(proxyServerPrivateKey);

	certBio = BIO_new(BIO_s_mem());
	BIO_write(certBio, proxyServerPrivateKey, cert_len);
	server_key = PEM_read_bio_PrivateKey(certBio, NULL, 0, NULL);
	BIO_free(certBio);
	
	if(!CA_key || !server_key){
		fprintf(stderr, "failed to init SSL certificate / keys, %p, %p\n", CA_key, server_key );
	}

	bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	pthread_mutex_unlock(&ssl_file_mutex);

}

void ssl_release(void)
{
	pthread_mutex_lock(&ssl_file_mutex);
	if ( CA_cert != NULL ) {
		X509_free(CA_cert);
		CA_cert = NULL;
	}
	
	if ( CA_key != NULL ) {
		EVP_PKEY_free(CA_key);
		CA_key = NULL;
	}

	if ( server_key != NULL ) {
		EVP_PKEY_free(server_key);
		server_key = NULL;
	}
	thread_cleanup();
	pthread_mutex_unlock(&ssl_file_mutex);
}
