#include <stdio.h>
#include <stdlib.h>

void malicious_function() {
    printf("Malicious function executed!\n");
    exit(0);
}

void victim_function() {
    char buffer[64];
    printf("Enter some text: ");
    gets(buffer);
    printf("You entered: %s\n", buffer);
}

int main() {
    printf("Starting victim program...\n");
    victim_function();
    printf("Exiting victim program...\n");
    return 0;
}
