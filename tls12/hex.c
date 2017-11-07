
#include "decrypt.h"


int xton(const char in)
{
    if(in >= '0' && in <= '9')
      return in - '0';
    if(in >= 'A' && in <= 'F')
      return in - 'A' + 10;
    if(in >= 'a' && in <= 'f')
      return in - 'a' + 10;

    return -1;
}

int from_hex(const char* in, char* out)
{
    size_t i;

    if(strlen(in) & 1)
        return -1;

    for (i = 0; i < strlen(in) / 2; i++)
    {
        int a = xton(in[i*2]);
        int b = xton(in[i*2 + 1]);
        if (a == -1 || b == -1)
            return -1;

        out[i] = a << 4 | b;
    }

    return out[i];
}
