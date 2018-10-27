
class UCCrypt
{
public:
    void Encipher(unsigned long *xl, unsigned long *xr);
    void Decipher(unsigned long *xl, unsigned long *xr);
private:
    unsigned long BlowFish(unsigned long x);
};
