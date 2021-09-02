#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <string>
#include <vector>
unsigned int reverse(unsigned int x)
{
    x = (x & 0x00FF00FF) << 8 | (x & 0xFF00FF00) >> 8;
    x = (x & 0x0000FFFF) << 16 | (x & 0xFFFF0000) >> 16;
    return x;
}

struct SDS_struct {
    uint32_t hash = 0;
    uint32_t id = 0;
    uint32_t size = 0;
    uint64_t offset = 0;
};

struct HEADER_struct {
    uint32_t USID_off = 0;
    uint32_t  GSID_off = 0;
    uint32_t SACL_off = 0;
    uint32_t DACL_off = 0;
};

struct ACL_struct {
    uint8_t revision = 0;
    uint8_t flag = 0;
    uint16_t size = 0;
    uint32_t count = 0;
    std::vector<struct ACE_struct> ace;
};

struct SID_struct {
    uint8_t revision;
    uint8_t authority[6];
    uint8_t number;
    std::vector<uint32_t> bytes;
};

struct ACE_struct {
    uint8_t type = 0;
    uint8_t flags = 0;
    uint16_t size = 0;
    uint32_t mask = 0;
    SID_struct SID;
};

int getDesc(FILE* f) {
    int first = ftell(f);
    SDS_struct sds;
    HEADER_struct header;
    ACL_struct audit_acl;
    ACL_struct perm_acl;
    struct SID_struct uSID;
    struct SID_struct gSID;
    
    //unsigned char two[2] = { 0x00 };
    unsigned char dword[4] = { 0x00 };
    unsigned char offset[8] = { 0x00 };
    unsigned char byte;
    

    fread(dword, 1, 4, f);
    memcpy(&sds.hash, dword, 4);
    
    //std::cout <<(int)dword[0]<<" "<< (int)dword[1] << " " << (int)dword[2] << " " << (int)dword[3] << std::endl;

    if (!sds.hash) return 0;

    fread(dword, 1, 4, f);
    memcpy(&sds.id, dword, 4);

    //std::cout << (int)dword[0] << " " << (int)dword[1] << " " << (int)dword[2] << " " << (int)dword[3] << std::endl;

    fread(offset, 1, 8, f);

    fread(dword, 1, 4, f);
    memcpy(&sds.size, dword, 4);

    fread(&byte, 1, 1, f);

    if (byte != 0x01) return -2;

    fread(&byte, 1, 1, f);

    if (byte != 0x00) return -3;

    fread(&byte, 1, 1, f);

    if (byte != 0x04) return -4;

    fread(&byte, 1, 1, f);

    fread(dword, 1, 4, f);
    memcpy(&header.USID_off, dword, 4);

    fread(dword, 1, 4, f);
    memcpy(&header.GSID_off, dword, 4);

    fread(dword, 1, 4, f);
    memcpy(&header.SACL_off, dword, 4);

    fread(dword, 1, 4, f);
    memcpy(&header.DACL_off, dword, 4);

    if (header.SACL_off != 0x00) {
        fseek(f, first + 20 + header.SACL_off, SEEK_SET);

        fread(&audit_acl.revision, 1, 1, f);

        fread(&byte, 1, 1, f);

        fread(&dword, 1, 2, f);
        memcpy(&audit_acl.size, dword, 2);

        fread(&dword, 1, 2, f);
        memcpy(&audit_acl.count, dword, 2);

        fread(&dword, 1, 2, f);

        //ACE_struct* ace = new ACE_struct[acl.count];

        //int k = 0;
        //unsigned char* arr = new unsigned char[sds.size];

        /*for (; ftell(f) < (first + sds.size); ++k ) fread(&arr[k], 1, 1, f);//arr[k++] = fgetc(f)
        arr[k] = 0x00;*/


        for (int i = 0; i < audit_acl.count; ++i) {
            struct ACE_struct ace;
            fread(&ace.type, 1, 1, f);
            fread(&ace.flags, 1, 1, f);
            fread(&dword, 1, 2, f);
            memcpy(&ace.size, dword, 2);

            fread(&dword, 1, 4, f);
            memcpy(&ace.mask, dword, 4);

            fread(&ace.SID.revision, 1, 1, f);

            fread(&ace.SID.authority, 1, 6, f);

            fread(&ace.SID.number, 1, 1, f);

            for (int g = 0; g < ((int)ace.size - 16); g += 4) {
                uint32_t dword_i = 0;
                fread(&dword, 1, 4, f);
                memcpy(&dword_i, dword, 4);
                ace.SID.bytes.push_back(dword_i);

            }
            audit_acl.ace.push_back(ace);
        }
    }


    if (header.DACL_off != 0x00) {
        fseek(f, first + 20 + header.DACL_off, SEEK_SET);

        fread(&perm_acl.revision, 1, 1, f);

        fread(&byte, 1, 1, f);

        fread(&dword, 1, 2, f);
        memcpy(&perm_acl.size, dword, 2);

        fread(&dword, 1, 2, f);
        memcpy(&perm_acl.count, dword, 2);

        fread(&dword, 1, 2, f);

        //ACE_struct* ace = new ACE_struct[acl.count];

        //int k = 0;
        //unsigned char* arr = new unsigned char[sds.size];

        /*for (; ftell(f) < (first + sds.size); ++k ) fread(&arr[k], 1, 1, f);//arr[k++] = fgetc(f)
        arr[k] = 0x00;*/


        for (int i = 0; i < perm_acl.count; ++i) {
            struct ACE_struct ace;
            fread(&ace.type, 1, 1, f);
            fread(&ace.flags, 1, 1, f);
            fread(&dword, 1, 2, f);
            memcpy(&ace.size, dword, 2);

            fread(&dword, 1, 4, f);
            memcpy(&ace.mask, dword, 4);

            fread(&ace.SID.revision, 1, 1, f);

            fread(&ace.SID.authority, 1, 6, f);

            fread(&ace.SID.number, 1, 1, f);

            for (int g = 0; g < ((int)ace.size - 16); g += 4) {
                uint32_t dword_i = 0;
                fread(&dword, 1, 4, f);
                memcpy(&dword_i, dword, 4);
                ace.SID.bytes.push_back(dword_i);

            }
            perm_acl.ace.push_back(ace);
        }
    }

    fseek(f, first + 20 + header.USID_off, SEEK_SET); 
    fread(&uSID.revision, 1, 1, f);
    fread(&uSID.authority, 1, 6, f);
    fread(&uSID.number, 1, 1, f);
    for (;ftell(f)< first + 20 + header.GSID_off; ) {
        uint32_t dword_i = 0;
        fread(&dword, 1, 4, f);
        memcpy(&dword_i, dword, 4);
        uSID.bytes.push_back(dword_i);
    }


    fseek(f, first + 20 + header.GSID_off, SEEK_SET);
    fread(&gSID.revision, 1, 1, f);
    fread(&gSID.authority, 1, 6, f);
    fread(&gSID.number, 1, 1, f);
    for (; ftell(f) < (first + sds.size); ) {
        uint32_t dword_i = 0;
        fread(&dword, 1, 4, f);
        memcpy(&dword_i, dword, 4);
        gSID.bytes.push_back(dword_i);
    }



    for (; ftell(f) %16 != 0; fseek(f, 1, SEEK_CUR));



    std::cout <<"NEW_RECORD:"<< sds.hash << " " << sds.id << " " << sds.size << " " << header.USID_off << " "
        << header.GSID_off << " " << header.SACL_off << " " << header.DACL_off ;
    std::cout << std::endl<< "audit_acl: ";
    if (audit_acl.size != 0x00) {
        std::cout << (int)audit_acl.revision << " " << (int)audit_acl.flag << " " << (int)audit_acl.size << " "
            << (int)audit_acl.count ;

            for (int i = 0; i < audit_acl.count; ++i) {
                std::cout << "\nACE["<<i<<"]: {" << (int)audit_acl.ace[i].type << " " << (int)audit_acl.ace[i].flags << " " << (int)audit_acl.ace[i].size << " "
                    << (int)audit_acl.ace[i].mask << " S-" << (int)audit_acl.ace[i].SID.revision << "-" << (int)audit_acl.ace[i].SID.authority[0] << "-" << (int)audit_acl.ace[i].SID.number;
                for (auto& h : audit_acl.ace[i].SID.bytes) std::cout << "-" << h;

                std::cout << "}";


            }

    }
    std::cout << std::endl << "perm_acl: ";

    if (perm_acl.size != 0x00) {
        std::cout  << (int)perm_acl.revision << " " <<  (int)perm_acl.flag << " " <<(int)perm_acl.size << " "
            << (int)perm_acl.count;

        for (int i = 0; i < perm_acl.count; ++i) {
            std::cout << "\nACE[" << i << "]: {" << (int)perm_acl.ace[i].type << " " << (int)perm_acl.ace[i].flags << " " << (int)perm_acl.ace[i].size << " "
                << (int)perm_acl.ace[i].mask << " S-" << (int)perm_acl.ace[i].SID.revision << "-" << (int)perm_acl.ace[i].SID.authority[0] << "-" << (int)perm_acl.ace[i].SID.number;
            for (auto& h : perm_acl.ace[i].SID.bytes) std::cout << "-" << h;
            std::cout << "}";


        }

    }

   std::cout << "\nUSER SID S-" << (int)uSID.revision << "-" << (int)uSID.authority[0] << "-" << (int)uSID.number;
    for (auto& h : uSID.bytes) std::cout << "-" << h;

    std::cout << "\nGROUP SID S-" << (int)gSID.revision << "-" << (int)gSID.authority[0] << "-" << (int)gSID.number;
    for (auto& h : gSID.bytes) std::cout << "-" << h;



    

    //std::cout << search;

    /*for (int i = 0; i < acl.count; ++i) {        
        std::cout << " ACE " << i << ": " << (int)ace[i].type<< " " << (int)ace[i].size << " " << (int)ace[i].mask <<" ";
        
        std::cout<<"S-"<<(int)ace[i].SID.revision << "-"<< (int)ace[i].SID.authority[0]<<"-" << 
            (int)ace[i].SID.number << "-"<< ace[i].SID.dword1 << "-" << ace[i].SID.dword2 << "-"
            << ace[i].SID.dword3 << "-"<< ace[i].SID.dword4 << "-" << ace[i].SID.dword5;

    }*/

        std::cout<< std::endl;
    //delete[] ace;
    //delete[] arr;
    return 1;

}




int main(int argc, char *argv[])
{
    if (argc< 2) return 2;
    std::cout << "Reading file "<<argv[1]<<std::endl;

    FILE* sds;
    sds = fopen(argv[1], "rb");

    if (!sds) {
        std::cout << "Error while read file " << argv[1]<<std::endl;
        return -1;
    }
    int ret = 0;
    do { ret = getDesc(sds); } while (ret == 1);

    std::cout << ret;
    return ret;
}

