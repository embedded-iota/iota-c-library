
#include <stdio.h>
#include <stdbool.h>


bool in_range(int x, int min, int max ){
    if(x >= min && x <= max){
        return true;
    }else{
        return false;
    }
}

size_t common_strnlen( const char * s, size_t maxlen )
{
    for( size_t len = 0; len != maxlen; len++ )
    {
        if(s[len] == '\0')
            return len;
    }
    return maxlen;
}