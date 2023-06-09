#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    int hostscan_icmp(QString s);
    int portscan_multhr(QString s,int pstart,int pend);

private:
    Ui::MainWindow *ui;

public slots:
    void host_scan();
    void port_scan();
};
#endif // MAINWINDOW_H
