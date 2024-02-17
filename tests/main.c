#include <stdio.h>
#include <string.h>

// gcc -o main main.c

int hexToDecimal(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    else if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    else if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    else
    {
        return -1; // Invalid character
    }
}

void convertToBytes(char *s, char *data)
{
    int len = strlen(s);
    for (int i = 0; i < len; i += 2)
    {
        data[i / 2] = (char)((hexToDecimal(s[i]) << 4) + hexToDecimal(s[i + 1]));
    }
}
int main()
{
    char *s = "abcdef123456";
    int len = strlen(s);
    char data[len / 2];
    convertToBytes(s, data);
    for (int i = 0; i < len / 2; i++)
    {
        printf("%02x ", data[i]);
    }
    printf("\n");
    return 0;
}