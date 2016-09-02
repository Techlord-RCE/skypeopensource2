// dump.c

#include <stdio.h>
#include <string.h>

//
// dump credentials to file
//
int dump_cred(char *user, char *p, char *q, char *credentials, int credentials_len) {
	FILE *fp;
	unsigned char *s, *pEnd;
	unsigned int i,j;
	char filename[] = "a_cred.txt";

	show_memory(p,0x40,"p bytes:");
	show_memory(q,0x40,"q bytes:");

    fp = fopen(filename, "w");

	if (!fp) {
		fprintf (stderr, "Cannot open file %s for writing\n", filename);
		return -1;
	}

	fprintf (fp, "%s:skypepass:FirstNameAndLastName:my@email.com:4.1.0.179:", user);

	// Credentials

    // finding credentials start, a bit dirty hack
    s=credentials;
    for(i=0; i<credentials_len; i++){
    	if (memcmp(s+i, "\x00\x00\x00\x01", 4) == 0) {
            s=s+i;
            break;
        };
    };
    
    pEnd=s+0x104;
	for (;s<pEnd; s++)
		fprintf (fp, "%02X", *s);
	fprintf (fp, ":");


	// Secret key (initial p - number)
	s=p;
	for (i=0; i<16; i++){
		// one 4-bytes chunk
		s=s+3;
		fprintf (fp, "%02X", *s);
		s--;
		fprintf (fp, "%02X", *s);
		s--;
		fprintf (fp, "%02X", *s);
		s--;
		fprintf (fp, "%02X", *s);
		s--;
		if (i<15) fprintf (fp, ".", *s);
		// prev 4-bytes chunk
		s=s+5;
	};
	fprintf (fp, ":");
	
	// Secret key (initial q - number)
	s=q;
	for (i=0; i<16; i++){
		// one 4-bytes chunk
		s=s+3;
		fprintf (fp, "%02X", *s);
		s--;
		fprintf (fp, "%02X", *s);
		s--;
		fprintf (fp, "%02X", *s);
		s--;
		fprintf (fp, "%02X", *s);
		s--;
		if (i<15) fprintf (fp, ".", *s);
		// prev 4-bytes chunk
		s=s+5;
	};

	fclose(fp);
	printf ("Credentials written to file %s\n", filename);

	return 0;
}
