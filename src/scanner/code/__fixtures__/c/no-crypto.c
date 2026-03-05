/* Test fixture: Plain C code with no cryptographic usage. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *msg = malloc(64);
    if (msg == NULL) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }
    strcpy(msg, "Hello, world!");
    printf("%s\n", msg);

    int nums[] = {3, 1, 4, 1, 5, 9};
    int sum = 0;
    for (int i = 0; i < 6; i++) {
        sum += nums[i];
    }
    printf("sum = %d\n", sum);

    free(msg);
    return 0;
}
