
int main(int argc, char* argv[]){
    char output[0x100];

    if (argc != 4) {
        printf("Number of input parameters wrong\n");
        return -1;
    };



    /*
    memset(output, 0x00, sizeof(output));
    skyrelay_main(argv[1], argv[2], argv[3], &output);
    printf("\nSuccess! Got remote version: %s\n\n", output);

    memset(output, 0x00, sizeof(output));
    skyrelay_main(argv[1], argv[2], argv[3], &output);
    printf("\nSuccess! Got remote version: %s\n\n", output);
    */

    memset(output, 0x00, sizeof(output));
    skyrelay_main(argv[1], argv[2], argv[3], &output);
    printf("\nSuccess! Got remote version: %s\n\n", output);

    return 0;
};
