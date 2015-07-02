#include "aes.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    AES w;
    w.show();
    return a.exec();
}
