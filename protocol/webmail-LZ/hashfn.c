#include  <stddef.h>

static inline 
size_t BKDRHash(const char *str)
{
	size_t ch;
    size_t hash = 0;  
    //while (ch = (size_t)*str++)
    //    hash = hash * 131 + ch;
	//    gcc may not optimize this code on X86_64
	while (ch = (size_t)*str++)
		hash = (hash << 7) + (hash << 1) + hash + ch;
    return hash;
}

static inline
unsigned int APHash(const char *str)
{
    unsigned int hash = 0;
    int i;
 
    for (i=0; *str; i++)
    {
        if ((i & 1) == 0)
        {
            hash ^= ((hash << 7) ^ (*str++) ^ (hash >> 3));
        }
        else
        {
            hash ^= (~((hash << 11) ^ (*str++) ^ (hash >> 5)));
        }
    }
 
    return (hash & 0x7FFFFFFF);
}
