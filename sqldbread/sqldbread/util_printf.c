//
// for my_printf_log -- debuglog
//

#include <stdio.h>
#include <stdarg.h>


int debuglog(const char *afmt, ...) {
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

    // to stdoout
	vprintf(afmt, args);

	va_end(args);

    return 0;
};
