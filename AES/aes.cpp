#include "aes.h"
#include "ui_aes.h"
#include <QFileDialog>
#define SC 4 // number of colomns of state (for AES SC = 4) Nb
// state is intermediate resulf of crypting (matrix 4*SC)
#define R 10 // number of rounds for crypting Nr
#define KL 4 // 4 * 32 = 128 Nk

unsigned char Sub_Matrix(unsigned char val);
unsigned char R_Sub_Matrix(unsigned char val);
void State_init(int choice);
void Key_init(unsigned char first_key[]);
void Data_init(unsigned char block[]);
void XorroundKey(int round);
void ShiftRows();
void InvShiftRows();
void SubBytes();
void InvSubBytes();
unsigned char mul_by_two(unsigned char val);
unsigned char mul_by_three(unsigned char val);
unsigned char mul_by_nine(unsigned char val);
unsigned char mul_by_B(unsigned char val);
unsigned char mul_by_D(unsigned char val);
unsigned char mul_by_E(unsigned char val);
void MixColumns();
void InvMixColumns();
void KeyGeneration();
void Encryption();
void Decryption();

unsigned char in[16], out[16], state[4][SC];
unsigned char Key[16];
unsigned char RoundKey[4][KL*(R+1)];
QString infile, outfile,keyin;
string input,s,output,key;

string IN, KF, B;
unsigned char rcon[4][R] = {
    {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
};

AES::AES(QWidget *parent) : QMainWindow(parent), ui(new Ui::AES)
{
    ui->setupUi(this);
}

AES::~AES()
{
    delete ui;
}

void AES::on_pushButton_clicked()
{
    infile=QFileDialog::getOpenFileName(this,tr("Открыть файл"),"/Users/","Allfiles(*)");
    IN = infile.toStdString();
ui->L2->setText(infile);
}
void AES::on_pushButton_2_clicked()
{
    keyin=QFileDialog::getOpenFileName(this,tr("Открыть файл"),"/Users/","Allfiles(*)");
    KF = keyin.toStdString();
ui->label->setText(keyin);

}

void AES::on_pushButton_3_clicked()
{
    //outfile=QFileDialog::getOpenFileName(this,tr("Открыть файл"),"/Users/","Allfiles(*)");
   // output = outfile.toStdString();
   // QString outfile=QFileDialog::getSaveFileName(this,tr("Открыть файл"),"/Users/","Allfiles(*");
   // string output = outfile.toStdString();
    //ofstream outp(output.c_str());

}
void AES::on_Decrypt_clicked()
{
    QString outfile=QFileDialog::getSaveFileName(this,tr("Открыть файл"),"/Users/","Allfiles(*");
    B = outfile.toStdString();
    FILE *fp = NULL;
    bool check[2] = {false,false};
    ifstream ink, inf, sf;
    ofstream ofst;

    unsigned char sch, buff[16],
    first_key[16] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}, //default key;
    block[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}; //default text
    int c = 0, lc = 0;
    long double S = 0, P =0;
    bool exit = false, quit = false;


        ui->Encrypt->setDisabled(true);
        ui->Decrypt->setDisabled(true);

        ink.open(KF.c_str(), ios::in);
        while (!ink.eof())
        {
           sch = ink.get();
           if (sch == EOF)
               break;
           buff[c] = sch;
           c++;
           if (c == 16)
               break;
        }
        for (int i = 0; i < 16; i++)
        {
            if (c != 16)
            first_key[i] = buff[i % (c-1)];
            if (c == 16)
            first_key[i] = buff[i % c];
        }

        ink.close();

        Key_init(first_key);



        sf.open(IN.c_str(), ios::binary|ios::in);
        sf.seekg(0, ios_base::end);
        S = sf.tellg();
        sf.seekg(0);
        sf.close();

        ofst.open(B.c_str(), ios::binary|ios::out);
        inf.open(IN.c_str(), ios::binary|ios::in);

        while(quit == false)
        {
              for(lc = 0; lc < 16; lc++)
              {
                  inf.read((char*)&sch, sizeof(sch));
                  if (inf.eof())
                  {
                      exit = true;
                      break;
                  }
                  buff[lc] = sch;
              }
              if (exit == true)
                  break;
              for (int i = 0; i < lc; i++)
              {
                   block[i] = buff[i];
              }

              QCoreApplication::processEvents();
              P = P + 1600/S;
              PBSV((int)P);
              setmytext("Progress...", 2);

              Data_init(block);
              KeyGeneration();
              Decryption();
              ofst.write((char*)out, 16);

         }

         ofst.close();
         inf.close();
         PBSV(0);
         setmytext("Decryption completed", 0);
         setmytext("", 2);
         ui->Encrypt->setEnabled(true);
         ui->Decrypt->setEnabled(true);

}

void AES::on_Encrypt_clicked()
{
    QString outfile=QFileDialog::getSaveFileName(this,tr("Открыть файл"),"/Users/","Allfiles(*");
   // string output = outfile.toStdString();
     B = outfile.toStdString();
    FILE *fp = NULL;
    bool check[2] = {false,false};
    ifstream ink, inf, sf;
    ofstream ofst;

    unsigned char sch, buff[16],
    first_key[16] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}, //default key;
    block[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}; //default text
    int c = 0, lc = 0;
    long double S = 0, P = 0;
    bool exit = false, quit = false;


        ui->Encrypt->setDisabled(true);
        ui->Decrypt->setDisabled(true);
  ink.open(KF.c_str(), ios::in);
        while (!ink.eof())
        {
           sch = ink.get();
           if (sch == EOF)
               break;
           buff[c] = sch;
           c++;
           if (c == 16)
               break;
        }
        for (int i = 0; i < 16; i++)
        {
            if (c != 16)
            first_key[i] = buff[i % (c-1)];
            if (c == 16)
            first_key[i] = buff[i % c];
        }

        ink.close();

        Key_init(first_key);


        sf.open(IN.c_str(), ios::binary|ios::in);
        sf.seekg(0, ios_base::end);
        S = sf.tellg();
        sf.seekg(0);
        sf.close();

        ofst.open(B.c_str(), ios::binary|ios::out);
        inf.open(IN.c_str(), ios::binary|ios::in);

        while(quit == false)
        {
             for(lc = 0; lc < 16; lc++)
             {
                 inf.read((char*)&sch, sizeof(sch));
                 if (inf.eof())
                 {
                      exit = true;
                      break;
                 }
                 buff[lc] = sch;
             }
             for (int i = 0; i < lc; i++)
             {
                  block[i] = buff[i];
             }
             for (int i = lc; i < 16; i++)
             {
                 //block[i] = 0x00;
                  block[i] = 0x20;
             }

             if (S <= 0 || S < 16)
                 S = 16;

             QCoreApplication::processEvents();
             P = P + double(1600/S);

             PBSV((int)P);


             Data_init(block);
             KeyGeneration();
             Encryption();

             ofst.write((char*)out, 16);

             if (exit == true)
                 quit = true;
        }
        ofst.close();
        inf.close();

        PBSV(0);


       // ui->Encrypt->setEnabled(true);
       // ui->Decrypt->setEnabled(true);


}

unsigned char Sub_Matrix(unsigned char val)
{
    unsigned char Sm[256] =
        {
        //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  //F
        };

        return Sm[val];
}
unsigned char R_Sub_Matrix(unsigned char val)
{
    unsigned char RSm[256] =
        {
        //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, //0
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, //1
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, //2
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, //3
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, //4
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, //5
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, //6
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, //7
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, //8
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, //9
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, //A
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, //B
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, //C
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, //D
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, //E
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d  //F
        };

        return RSm[val];
}
void XorroundKey(int round)
{
    unsigned char s1, s2, s3, s4;
        for (int j = 0; j < KL; j++)
        {
            s1 = state[0][j] ^ RoundKey[0][round*SC + j];
            s2 = state[1][j] ^ RoundKey[1][round*SC + j];
            s3 = state[2][j] ^ RoundKey[2][round*SC + j];
            s4 = state[3][j] ^ RoundKey[3][round*SC + j];

            state[0][j] = s1;
            state[1][j] = s2;
            state[2][j] = s3;
            state[3][j] = s4;
        }
}
void KeyGeneration()
{
    unsigned char temp[4], k;

        for(int i = 0; i < 4; i++)
        {
            for(int j = 0; j < KL; j++)
            {
                RoundKey[i][j] = Key[i + 4*j];
            }
        }
        for(int i = KL; i < KL*(R+1); i++)
        {
            for (int j = 0; j < 4; j++)
            {
                temp[j] = RoundKey[j][i-1];
            }

            if (i % KL == 0)
            {
                k = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = k;

                for (int j = 0; j < 4; j++)
                {
                    temp[j]= Sub_Matrix(temp[j]);
                }


                for (int j = 0; j < 4; j++)
                    temp[j] = (RoundKey[j][i-KL]) ^ (temp[j]) ^ (rcon[j][i/KL-1]);

            }
            else
            {
                for (int j = 0; j < 4; j++)
                    temp[j] = RoundKey[j][i-KL] ^ RoundKey[j][i-1]; // temp[j] = temp[j] ^ RoundKey[j][i-KL];

            }
            for (int j = 0; j < 4; j++)
                RoundKey[j][i] = temp[j];
        }
}
void State_init(int choice)
{
    if (choice == 0)
        {
            for(int i = 0; i < 4; i++)
            {
                for(int j = 0; j < 4; j++)
                    state[i][j] = in[i + j*4];
            }
        }
        if (choice == 1)
        {
            for(int i = 0; i < 4; i++)
            {
                for(int j = 0; j < 4; j++)
                    state[i][j] = out[i + j*4];
            }
        }
}
void Key_init(unsigned char first_key[])
{
    for(int i = 0; i < 16; i++)
        {
            Key[i] = first_key[i];
        }
}
void Data_init(unsigned char block[])
{
    for(int i = 0; i < 16; i++)
        {
            in[i] = block[i];
        }
}
void ShiftRows()
{
    unsigned char temp;

        // Rotate first row 1 columns to left
        temp=state[1][0];
        state[1][0]=state[1][1];
        state[1][1]=state[1][2];
        state[1][2]=state[1][3];
        state[1][3]=temp;

        // Rotate second row 2 columns to left
        temp=state[2][0];
        state[2][0]=state[2][2];
        state[2][2]=temp;

        temp=state[2][1];
        state[2][1]=state[2][3];
        state[2][3]=temp;

        // Rotate third row 3 columns to left
        temp=state[3][0];
        state[3][0]=state[3][3];
        state[3][3]=state[3][2];
        state[3][2]=state[3][1];
        state[3][1]=temp;
}
void InvShiftRows()
{
    unsigned char temp;

        // Rotate first row 1 columns to right
        temp=state[1][3];
        state[1][3]=state[1][2];
        state[1][2]=state[1][1];
        state[1][1]=state[1][0];
        state[1][0]=temp;

        // Rotate second row 2 columns to right
        temp=state[2][0];
        state[2][0]=state[2][2];
        state[2][2]=temp;

        temp=state[2][1];
        state[2][1]=state[2][3];
        state[2][3]=temp;

        // Rotate third row 3 columns to right
        temp=state[3][0];
        state[3][0]=state[3][1];
        state[3][1]=state[3][2];
        state[3][2]=state[3][3];
        state[3][3]=temp;
}
void SubBytes()
{
    for(int i = 0; i < 4; i++)
    {
         for(int j = 0; j < 4; j++)
         {
             state[i][j] = Sub_Matrix(state[i][j]);
         }
    }
}
void InvSubBytes()
{
     for(int i = 0; i < 4; i++)
     {
         for(int j = 0; j < 4; j++)
         {
             state[i][j] = R_Sub_Matrix(state[i][j]);
         }
     }
}
void MixColumns()
{
    unsigned char s1, s2, s3, s4;
    for (int j = 0; j < 4; j++)
    {
         s1 = mul_by_two(state[0][j]) ^ mul_by_three(state[1][j]) ^ state[2][j] ^ state[3][j];
         s2 = state[0][j] ^ mul_by_two(state[1][j]) ^ mul_by_three(state[2][j]) ^ state[3][j];
         s3 = state[0][j] ^ state[1][j] ^ mul_by_two(state[2][j]) ^ mul_by_three(state[3][j]);
         s4 = mul_by_three(state[0][j]) ^ state[1][j] ^ state[2][j] ^ mul_by_two(state[3][j]);
         state[0][j] = s1;
         state[1][j] = s2;
         state[2][j] = s3;
         state[3][j] = s4;
    }
}
void InvMixColumns()
{
    unsigned char s1, s2, s3, s4;
    for (int j = 0; j < 4; j++)
    {
         s1 = mul_by_E(state[0][j]) ^ mul_by_B(state[1][j]) ^ mul_by_D(state[2][j]) ^ mul_by_nine(state[3][j]);
         s2 = mul_by_nine(state[0][j]) ^ mul_by_E(state[1][j]) ^ mul_by_B(state[2][j]) ^ mul_by_D(state[3][j]);
         s3 = mul_by_D(state[0][j]) ^ mul_by_nine(state[1][j]) ^ mul_by_E(state[2][j]) ^ mul_by_B(state[3][j]);
         s4 = mul_by_B(state[0][j]) ^ mul_by_D(state[1][j]) ^ mul_by_nine(state[2][j]) ^ mul_by_E(state[3][j]);

         state[0][j] = s1;
         state[1][j] = s2;
         state[2][j] = s3;
         state[3][j] = s4;
    }
}
unsigned char mul_by_two(unsigned char val)
{
    if (val < 0x80)
            val = val << 1;
        else
            val = (val << 1) ^ 0x1b;

        return val % 0x100;
}
unsigned char mul_by_three(unsigned char val)
{
    return (mul_by_two(val) ^ val);
}
unsigned char mul_by_nine(unsigned char val)
{
    return (mul_by_two(mul_by_two(mul_by_two(val))) ^ val);
}
unsigned char mul_by_B(unsigned char val)
{
    return (mul_by_two(mul_by_two(mul_by_two(val))) ^ mul_by_two(val) ^ val);
}
unsigned char mul_by_D(unsigned char val)
{
    return (mul_by_two(mul_by_two(mul_by_two(val))) ^ mul_by_two(mul_by_two(val)) ^ val);
}
unsigned char mul_by_E(unsigned char val)
{
    return (mul_by_two(mul_by_two(mul_by_two(val))) ^ mul_by_two(mul_by_two(val)) ^ mul_by_two(val));
}
void Encryption()
{
    State_init(0);

    XorroundKey(0);

    for(int round = 1; round < R; round++)
    {
        SubBytes();
        ShiftRows();
        MixColumns();

        XorroundKey(round);

    }

    SubBytes();
    ShiftRows();
    XorroundKey(R);

    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            out[i*4 + j] = state[j][i];
        }
    }
}
void Decryption()
{
    State_init(0);
  //State_init(1);

    XorroundKey(R);

    for(int round = R-1; round > 0; round--)
    {
        InvShiftRows();
        InvSubBytes();
        XorroundKey(round);
        InvMixColumns();
    }

    InvShiftRows();
    InvSubBytes();
    XorroundKey(0);

    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            out[i*4+j] = state[j][i];
        }
    }
}
bool AES::CheckExistance(FILE *fp, char str[])
{
    fp = fopen(str,"r");
    if (fp == NULL)
    {

        return false;
    }
    fclose(fp);
    return true;
}
char *AES::ret(int key)
{

}
void AES::setmytext(QString mystr, int key)
{

}
void AES::PBSV(int val)
{

}


