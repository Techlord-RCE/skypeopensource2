// vcard_save.c array forming, check for uniq, and save to file
//

#include <stdio.h>
#include <stdlib.h>

#include <string.h>

char *arr_vcards[0x100];
int arr_len;


int init_vcard_array(){
    FILE *fp;
        
    fp = fopen("_result.txt","w");
    fclose(fp);

    arr_vcards[0] = NULL;
    arr_len = 0;

    return 0;
};


int add_vcard(char *vcardstr){
    char *vcard;
    int i;
    int len;

    // need to check on dublicate
    // with memcmp
    len = strlen(vcardstr);
    for(i=0;i<arr_len;i++) {
        vcard = arr_vcards[i];
        // match with previous vcard, nothing to do
        if (memcmp(vcard, vcardstr, len) == 0) {
            return 0;
        };
    };

    // no matches with prevoius vcards, add this new vcard to array
    arr_vcards[arr_len] = strdup(vcardstr);
    arr_len++;

    return 0;
};


int save_vcards_tofile(){
    FILE *fp;
    char *vcard;
    int i;

    printf("Saving unique vcards array to file.\n");

    fp = fopen("_result.txt","w");

    for(i=0;i<arr_len;i++) {
        vcard = arr_vcards[i];
        printf("%s",vcard);
        fprintf(fp,"%s",vcard);
    };

    fclose(fp);

    printf("End of unique vcards array saving.\n\n");

    return 0;
};


int save_vcards_tomem(char *vcard_buf, int maxlen){
    char *vcard;
    int i;
    int buflen;
    int buf_remain;

    printf("Saving unique vcards array to mem.\n");

    buflen = 0;
    for(i=0;i<arr_len;i++) {
        vcard = arr_vcards[i];
        printf("%s",vcard);
        buf_remain = maxlen - buflen;
        strncpy(vcard_buf+buflen, vcard, buf_remain);
        buflen += strlen(vcard);
    };

    printf("End of unique vcards array saving to mem.\n\n");

    return buflen;
};
