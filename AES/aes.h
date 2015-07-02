#ifndef AES_H
#define AES_H

#include <QMainWindow>
#include <QDir>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <unistd.h>
using namespace std;


namespace Ui
{
    class AES;
}

class AES : public QMainWindow
{
    Q_OBJECT

public:
    explicit AES(QWidget *parent = 0);
    bool CheckExistance(FILE *fp, char str[]);
    char *ret(int key);
    void setmytext(QString mystr, int key);
    void PBSV(int val);
    ~AES();

private slots:
    void on_Decrypt_clicked();

    void on_Encrypt_clicked();
     void on_pushButton_clicked();
void on_pushButton_2_clicked();
void on_pushButton_3_clicked();
private:
    Ui::AES *ui;
};

#endif // AES_H
