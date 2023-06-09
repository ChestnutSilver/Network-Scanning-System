#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QLabel>
#include <QTextBrowser>
#include <QMessageBox>


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setWindowTitle("网络扫描器");
    ui->tabWidget->setTabText(0, "主机扫描");
    ui->tabWidget->setTabText(1, "端口扫描");
    connect(ui->pB_ho_start, SIGNAL(clicked()), this, SLOT(host_scan()));
    connect(ui->pB_po_start, SIGNAL(clicked()), this, SLOT(port_scan()));
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::host_scan(){


    QString subnet = QString("%1.%2.%3.")
                .arg(ui->spinBox->value())
                .arg(ui->spinBox_2->value())
                .arg(ui->spinBox_3->value());
    QString temp = "当前扫描"+subnet+"0/24网段";
    ui->label_5->setText(temp);
    ui->textB_host->setPlainText("下面为该网段开放主机：");

    hostscan_icmp(subnet);
}


void MainWindow::port_scan(){

    ui->textB_port->clear();
    QString ip = QString("%1.%2.%3.%4")
                .arg(ui->spinBox_4->value())
                .arg(ui->spinBox_5->value())
                .arg(ui->spinBox_6->value())
                .arg(ui->spinBox_7->value());
    int pstart=ui->spinBox_8->value();
    int pend=ui->spinBox_9->value();
    if(pstart>pend){
        ui->label_10->setText("");
        QMessageBox::critical(this,"输入错误","起始端口号大于结束端口号");
    }
    else{
        QString temp = "当前扫描"+ip+",端口号范围"+QString::number(pstart)+"~"+QString::number(pend);
        ui->label_10->setText(temp);
        ui->textB_port->setPlainText("下面为该地址端口范围内开放端口号：");

        portscan_multhr(ip,pstart,pend);
    }
}
