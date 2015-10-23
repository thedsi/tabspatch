#include <stdio.h>
#include <tchar.h>
#include <vector>
#include <string>
#include <algorithm>
using namespace std;

unsigned char sig[] = { 0x6A, 0xFF, 0x68, 0xAA, 0xAA, 0xAA, 0xAA, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x50, 0x81, 0xEC, 0x70, 0x05, 0x00, 0x00 };
unsigned char patch[] = { 0x33, 0xC0, 0xC3 };

void *FindFunction(void *mem, size_t memsize, const unsigned char* Sig, size_t SigSize)
{
    unsigned char *p = (unsigned char*)mem;
    unsigned char *endp = p + memsize - SigSize;
    bool bFound = false;
    void *AddressFound = NULL;
    unsigned int i;
    do
    {
        i = 0;
        while (Sig[i] == p[i] || Sig[i] == 0xAA) { //AA = wildcard
            i++;
            if (i == SigSize) {
                if (bFound) return NULL; //two different matches for sig
                bFound = true;
                AddressFound = p;
                break;
            }
        }
        p += 1;
    } while (p <= endp);
    return AddressFound;
}


int wmain(int argc, wchar_t** argv)
{
    printf("Tabs Studio Crack 2015-10-23\n");
    if (argc != 2)
    {
        printf("Syntax: %s <TabsStudio.dll>\n", argv[0]);
        return 1;
    }

    FILE *file = _wfopen(argv[1], L"rb");
    if (!file)
    {
        printf("Unable to open %s\n", argv[1]);
        return 1;
    }
    fseek(file, 0, SEEK_END);
    size_t filesize = ftell(file);
    fseek(file, 0, SEEK_SET);
    vector<uint8_t> buffer;
    buffer.resize(filesize);
    bool success = (fread(buffer.data(), 1, filesize, file) == filesize);
    fclose(file);
    if (!success)
    {
        printf("Unable to read file %s\n",argv[1]);
        return 1;
    }
    
    unsigned char *p = (unsigned char*)FindFunction(buffer.data(), buffer.size(), sig, sizeof(sig));
    if (!p)
    {
        printf("Signature search failed");
        return 1;
    }
    wstring orig = argv[1] + wstring(L"orig");
    FILE* fbackup = _wfopen(orig.c_str(), L"wb");
    if (fbackup)
    {
        printf("Writing backup\n");
        fwrite(buffer.data(), 1, buffer.size(), fbackup);
        fclose(fbackup);
    }
    printf("Patching (%p)...\n", p - &buffer.front());
    copy(patch, patch + sizeof(patch), p);
    
    FILE* fnew = _wfopen(argv[1], L"wb");
    if (fnew)
    {
        printf("Writing...\n");
        fwrite(buffer.data(), 1, buffer.size(), fnew);
        fclose(fnew);
    }
    else
    {
        printf("Cannot open file for writing %s\n", argv[1]);
        return 1;
    }
    return 0;
}