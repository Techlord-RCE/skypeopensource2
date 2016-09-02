//
// for my_printf_log -- debuglog
//

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

// windows specific
#include <windows.h>


int debuglog(const char *afmt, ...) {
    FILE *log;
	va_list args;
    
    //return 0;

    log=fopen("_mylog.txt","a");
    if (log == NULL){
        printf("logfile creation error\n");
        return -10;
    };

	va_start(args, afmt);

	vfprintf(log, afmt, args);
	//fprintf(log, "File: \"%s\", Line: %d\n", __File__, __Line__);
	fclose(log);

    // to stdout
	vprintf(afmt, args);

	va_end(args);

    return 0;
};


int debuglog_info(const char *afmt, ...) {
    FILE *log;
	va_list args;
    

    log=fopen("_mylog.txt","a");
    if (log == NULL){
        printf("logfile creation error\n");
        return -10;
    };

	va_start(args, afmt);

	vfprintf(log, afmt, args);
	//fprintf(log, "File: \"%s\", Line: %d\n", __File__, __Line__);
	fclose(log);

    // to stdout
	//vprintf(afmt, args);

	va_end(args);

    return 0;
};


int debuglog_err(const char *afmt, ...) {
    FILE *log;
	va_list args;
    

    log=fopen("_mylog.txt","a");
    if (log == NULL){
        printf("logfile creation error\n");
        return -10;
    };

	va_start(args, afmt);

	vfprintf(log, afmt, args);
	//fprintf(log, "File: \"%s\", Line: %d\n", __File__, __Line__);
	fclose(log);

    // to stdout
	//vprintf(afmt, args);

	va_end(args);

    return 0;
};


int debuglog_time(const char *afmt, ...) {
    FILE *log;
	va_list args;
    time_t timer;
    struct tm* tm_info;
    char timebuf[256];

	// windows specific
	DWORD dwStart;

	dwStart = GetTickCount();

    // for linux
	//struct timeval tv;
    // for microseconds
    //gettimeofday(&tv,NULL);
    
	memset(timebuf, 0, sizeof(timebuf));

    //get current time
    time(&timer);
    tm_info = localtime(&timer);
    strftime(timebuf, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    //sprintf(timebuf, ".%d", tv.tv_user);
	sprintf(timebuf+strlen(timebuf), ".%d", dwStart/10000);

    log=fopen("_mylog.txt","a");
    if (log == NULL){
        printf("logfile creation error\n");
        return -10;
    };

	va_start(args, afmt);

	fprintf(log, "%s ", timebuf);
	vfprintf(log, afmt, args);
	//fprintf(log, "File: \"%s\", Line: %d\n", __File__, __Line__);
	fclose(log);

    // to stdout
	//printf("%s ", timebuf);
	vprintf(afmt, args);

	va_end(args);

    return 0;
};


int debuglog_notime(const char *afmt, ...) {
    FILE *log;
	va_list args;
    
    return 0;

    log=fopen("_mylog.txt","a");
    if (log == NULL){
        printf("logfile creation error\n");
        return -10;
    };

	va_start(args, afmt);

	vfprintf(log, afmt, args);
	//fprintf(log, "File: \"%s\", Line: %d\n", __File__, __Line__);
	fclose(log);

    // to stdout
	vprintf(afmt, args);

	va_end(args);

    return 0;
};
