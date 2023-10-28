#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QString>
#include "multithread.h"
#include <QDebug>
#include <string.h>
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    statusBar()->showMessage("welcome_to_my_shark~~~");
    ui->toolBar->addAction(ui->actionrunandstop);
    ui->toolBar->addAction(ui->actionclear);
    count = 0;
    selectRow = -1;
    showNetworkCard();
    multithread*thread = new multithread;
    static bool index = false;
    connect(ui->actionrunandstop,&QAction::triggered,this,[=](){
        index = !index;
        if(index){
            //清空上次运行的数据,释放掉上一次申请的qvector内存
            ui->tableWidget->clearContents();
            ui->tableWidget->setRowCount(0);
            count = 0;
            selectRow = -1;
            int dataSize = this->pData.size();
            for(int i = 0; i < dataSize; i++){
                free((char*)(this->pData[i].pkt_content));
                this->pData[i].pkt_content = nullptr;
            }
            //真正释放内存不能用clear，而是要和空的容器进行内存交换
            QVector<dataPackage>().swap(pData);

            //然后再开始捕获
            int res = capture();
            if(res != -1 && pointer){             
                thread->setPointer(pointer);
                thread->setFlag();
                thread->start();
                ui->actionrunandstop->setIcon(QIcon(":/Pause.png"));
                ui->comboBox->setEnabled(false);    //不可点击
            }
            else{
                //非物理网卡可能捕获不到
                index = !index;
                count = 0;
            }
        }
        else{
            thread->quit();
            thread->resetFlag();
            ui->actionrunandstop->setIcon(QIcon(":/start.png"));
            ui->comboBox->setEnabled(true);
            //注意释放掉pointer，避免野指针
            pcap_close(pointer);
            pointer = nullptr;
        }
    });
    //信号和槽的松耦合机制，参数：信号发送者，发送者地址，接收者，接收者地址
    connect(thread,&multithread::send,this,&MainWindow::haddleMessage);
    ui->tableWidget->setColumnCount(7);
    ui->tableWidget->setColumnWidth(0,50);
    ui->tableWidget->setColumnWidth(1,150);
    ui->tableWidget->setColumnWidth(2,150);
    ui->tableWidget->setColumnWidth(3,150);
    ui->tableWidget->setColumnWidth(4,150);
    ui->tableWidget->setColumnWidth(5,150);
    ui->tableWidget->setColumnWidth(6,150);

    ui->tableWidget->verticalHeader()->setDefaultSectionSize(30);
    QStringList title = {"No.","Time","Source","Destination","protocal","lenth","info"};
    ui->tableWidget->setHorizontalHeaderLabels(title);

    //去掉序列
    ui->tableWidget->verticalHeader()->setVisible(false);
    //点击即选中一行
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    //隐藏detail的header
    ui->treeWidget->setHeaderHidden(true);
}

MainWindow::~MainWindow()
{
    //和run函数刚开始的操作一样，先清空
    int datasize = pData.size();
    for(int i = 0; i < datasize; i++){
        free((char*)(this->pData[i].pkt_content));
        this->pData[i].pkt_content = nullptr;
    }
    QVector<dataPackage>().swap(pData);
    delete ui;
}

void MainWindow::showNetworkCard(){
    //显示全部的网卡设备
    int n = pcap_findalldevs(&allDevice,errorBuff);
    if(n == -1){
        ui->comboBox->addItem("error: " + QString(errorBuff));
    }
    else{
        ui->comboBox->clear();
        ui->comboBox->addItem("please choose card");
        for(device = allDevice; device != nullptr; device = device->next){
            QString deviceName = device->name;
            deviceName.replace("\\Device\\","");
            QString deviceDescription = device->description;
            QString deviceItem = deviceName + deviceDescription;
            ui->comboBox->addItem(deviceItem);
        }
    }
}

void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    int i = 0;
    if(index != 0){
        for(device = allDevice; i < index - 1; device = device->next,i++);
    }
    return;
}

int MainWindow::capture(){
//    if(device){
//        pointer = pcap_open_live(device->name,65536,1,1000,errorBuff);
//    }
//    else{
//        return -1;
//    }

//    if(!pointer){
//        //pointer可能为空，避免出现野指针
//        pcap_freealldevs(allDevice);
//        device = nullptr;
//        return -1;
//    }
//    else{
//        //只针对满足IEEE 802.3协议的数据包进行捕获，其他数据包丢弃
//        if(pcap_datalink(pointer) != DLT_EN10MB){
//            pcap_close(pointer);
//            pcap_freealldevs(allDevice);
//            pointer = nullptr;
//            device = nullptr;
//            return -1;
//        }
//        statusBar()->showMessage(device->name);
//    }

    if(device){
        pointer = pcap_open_live(device->name,65536,1,1000,errorBuff);
        //只针对满足IEEE 802.3协议的数据包进行捕获，其他数据包丢弃
        if(pointer && pcap_datalink(pointer) == DLT_EN10MB){
            statusBar()->showMessage(device->name);
        }
        else{
            pcap_close(pointer);
            pcap_freealldevs(allDevice);
            pointer = nullptr;
            device = nullptr;
            return -1;
        }
    }
    else{
        return -1;
    }

    return 0;

}

void MainWindow::haddleMessage(dataPackage data){
    qDebug()<<data.getTime()<<" "<<data.getInfo()<<" "<<data.getLenth()<<data.getPackageType();
    ui->tableWidget->insertRow(count);
    this->pData.push_back(data);
    QString type = data.getPackageType();
    QColor color;
    if(type == "ARP") color  = QColor(123, 0, 123);
    else if(type == "ICMP") color  = QColor(0, 123, 123);
    else if(type == "UDP") color  = QColor(123, 123, 123);
    else if(type == "TCP") color  = QColor(193, 210, 240);
    else if(type == "DNS") color  = QColor(123, 123, 123);
    else if(type == "TLS") color  = QColor(0, 0, 255);
    else color  = QColor(25, 0, 0);

    ui->tableWidget->setItem(count,0,new QTableWidgetItem(QString::number(count)));
    ui->tableWidget->setItem(count,1,new QTableWidgetItem(data.getTime()));
    ui->tableWidget->setItem(count,2,new QTableWidgetItem(data.getSource()));
    ui->tableWidget->setItem(count,3,new QTableWidgetItem(data.getDestination()));
    ui->tableWidget->setItem(count,4,new QTableWidgetItem(data.getPackageType()));
    ui->tableWidget->setItem(count,5,new QTableWidgetItem(data.getLenth()));
    ui->tableWidget->setItem(count,6,new QTableWidgetItem(data.getInfo()));
    for(int i = 0; i < 7; i++){
        ui->tableWidget->item(count,i)->setBackgroundColor(color);
    }
    count++;
}

void MainWindow::on_tableWidget_cellClicked(int row, int column)
{
    if(row == selectRow || row < 0){  //一直在点或者没有点击，都是无效动作
        return;
    }
    else{//点击新的一行
        ui->treeWidget->clear();
        selectRow = row;
        if(selectRow < 0 || selectRow > count){
            return;
        }
        QString desMac = pData[selectRow].getDesMac();
        QString srcMac = pData[selectRow].getSrcMac();
        QString type = pData[selectRow].getMacType();
        QString EtherTree = "Ethernet src:" + srcMac + " des:" + desMac + " type:" + type;
        QTreeWidgetItem*EtherItem = new QTreeWidgetItem(QStringList()<<EtherTree);
        ui->treeWidget->addTopLevelItem(EtherItem);
        EtherItem->addChild(new QTreeWidgetItem(QStringList()<< "Destination:" + desMac));
        EtherItem->addChild(new QTreeWidgetItem(QStringList()<< "Source:" + srcMac));
        EtherItem->addChild(new QTreeWidgetItem(QStringList()<< "type:" + type));

        QString packageType = pData[selectRow].getPackageType();

        /*IP*/
        QString desIP = pData[selectRow].getIPdesAdd();
        QString srcIP = pData[selectRow].getIPsrcAdd();
        QString version = pData[selectRow].getIPVersion();
        QString headLen = pData[selectRow].getIPHeadLenth();
        QString Tos = pData[selectRow].getIpTos();
        QString identification = "0x" + pData[selectRow].getIPIdentification();
        QString flags = pData[selectRow].getIpFlag();
        if(flags.size()<2)
            flags = "0" + flags;
        flags = "0x" + flags;
        QString FragmentOffset = pData[selectRow].getIpFragmentOffset();
        QString totalLenth = pData[selectRow].getIPTotalLenth();
        QString ttl = pData[selectRow].getIPTTL();
        QString protocal = pData[selectRow].getIPProtocal();
        QString checksum = "0x" + pData[selectRow].getIPChecksum();
        QTreeWidgetItem*ipItem = new QTreeWidgetItem(QStringList()<<"Internet Protocol Version 4, Src:" + srcIP + ", Dst:" + desIP);
        ui->treeWidget->addTopLevelItem(ipItem);
        int dataLengthofIp = totalLenth.toUtf8().toInt() - 20;
        ipItem->addChild(new QTreeWidgetItem(QStringList()<< "0100 .... = Version:" + version));
        ipItem->addChild(new QTreeWidgetItem(QStringList()<< ".... 0101 = Head Lenth:" + headLen));
        ipItem->addChild(new QTreeWidgetItem(QStringList()<< "TOS:" + Tos));
        ipItem->addChild(new QTreeWidgetItem(QStringList()<< "Total Lenth:" + totalLenth));
        ipItem->addChild(new QTreeWidgetItem(QStringList()<< "identification:" + identification));

        QString reservedBit = pData[selectRow].getIpReservedBit();
        QString DF = pData[selectRow].getIpDF();
        QString MF = pData[selectRow].getIpMF();
        QString FLAG = ",";

        if(reservedBit == "1"){
            FLAG += "Reserved bit";
        }
        else if(DF == "1"){
            FLAG += "Don't fragment";
        }
        else if(MF == "1"){
            FLAG += "More fragment";
        }
        if(FLAG.size() == 1)
            FLAG = "";
        QTreeWidgetItem*bitTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flags + FLAG);
        ipItem->addChild(bitTree);
        QString temp = reservedBit == "1"?"Set":"Not set";
        bitTree->addChild(new QTreeWidgetItem(QStringList()<<reservedBit + "... .... = Reserved bit:" + temp));
        temp = DF == "1"?"Set":"Not set";
        bitTree->addChild(new QTreeWidgetItem(QStringList()<<"." + DF + ".. .... = Don't fragment:" + temp));
        temp = MF == "1"?"Set":"Not set";
        bitTree->addChild(new QTreeWidgetItem(QStringList()<<".." + MF + ". .... = More fragment:" + temp));

        ipItem->addChild(new QTreeWidgetItem(QStringList()<< "ttl:" + ttl));
        ipItem->addChild(new QTreeWidgetItem(QStringList()<< "protocal:" + protocal));
        ipItem->addChild(new QTreeWidgetItem(QStringList()<< "checksum:" + checksum));
        ipItem->addChild(new QTreeWidgetItem(QStringList()<<"Source Address:" + srcIP));
        ipItem->addChild(new QTreeWidgetItem(QStringList()<<"Destination Address:" + desIP));

        if(packageType == "TCP"){
            QString desPort = pData[selectRow].getTcpDestinationPort();
            QString srcPort = pData[selectRow].getTcpSourcePort();
            QString ack = pData[selectRow].getTcpAcknowledgment();
            QString seq = pData[selectRow].getTcpSequence();
            QString headerLength = pData[selectRow].getTcpHeaderLength();
            int rawLength = pData[selectRow].getTcpRawHeaderLength().toUtf8().toInt();
            dataLengthofIp -= (rawLength * 4);
            QString dataLength = QString::number(dataLengthofIp);
            QString flag = pData[selectRow].getTcpFlags();
            while(flag.size()<2)
                flag = "0" + flag;
            flag = "0x" + flag;
            QTreeWidgetItem*item4 = new QTreeWidgetItem(QStringList()<<"Transmission Control Protocol, Src Port:" + srcPort + ", Dst Port:" + desPort + ",Seq:" + seq + ", Ack:" + ack + ", Len:" + dataLength);

            ui->treeWidget->addTopLevelItem(item4);
            item4->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:" + srcPort));
            item4->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:" + desPort));
            item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number (raw) :" + seq));
            item4->addChild(new QTreeWidgetItem(QStringList()<<"Ackowledgment Number (raw) :" + ack));
            QString sLength = QString::number(rawLength,2);
            while(sLength.size()<4)
                sLength = "0" + sLength;
            item4->addChild(new QTreeWidgetItem(QStringList()<<sLength + " .... = Header Length:" + headerLength));

            QString PSH = pData[selectRow].getTcpPSH();
            QString URG = pData[selectRow].getTcpURG();
            QString ACK = pData[selectRow].getTcpACK();
            QString RST = pData[selectRow].getTcpRST();
            QString SYN = pData[selectRow].getTcpSYN();
            QString FIN = pData[selectRow].getTcpFIN();
            QString FLAG = "";

            if(PSH == "1")
                FLAG += "PSH,";
            if(URG == "1")
                FLAG += "UGR,";
            if(ACK == "1")
                FLAG += "ACK,";
            if(RST == "1")
                FLAG += "RST,";
            if(SYN == "1")
                FLAG += "SYN,";
            if(FIN == "1")
                FLAG += "FIN,";
            FLAG = FLAG.left(FLAG.length()-1);
            if(SYN == "1"){
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 0 (relative ack number)"));
            }
            if(SYN == "1" && ACK == "1"){
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 1 (relative ack number)"));
            }
            QTreeWidgetItem*flagTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flag + " (" + FLAG + ")");
            item4->addChild(flagTree);
            QString temp = URG == "1"?"Set":"Not set";
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .." + URG + ". .... = Urgent(URG):" + temp));
            temp = ACK == "1"?"Set":"Not set";
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ..." + ACK + " .... = Acknowledgment(ACK):" + temp));
            temp = PSH == "1"?"Set":"Not set";
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... " + PSH + "... = Push(PSH):" + temp));
            temp = RST == "1"?"Set":"Not set";
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ." + RST + ".. = Reset(RST):" + temp));
            temp = SYN == "1"?"Set":"Not set";
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... .." + SYN + ". = Syn(SYN):" + temp));
            temp = FIN == "1"?"Set":"Not set";
            flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ..." + FIN + " = Fin(FIN):" + temp));
            QString window = pData[selectRow].getTcpWindowSize();
            QString checksum = "0x" + pData[selectRow].getTcpCheckSum();
            QString urgent = pData[selectRow].getTcpUrgentPointer();
            item4->addChild(new QTreeWidgetItem(QStringList()<<"window:" + window));
            item4->addChild(new QTreeWidgetItem(QStringList()<<"checksum:" + checksum));
            item4->addChild(new QTreeWidgetItem(QStringList()<<"Urgent Pointer:" + urgent));
        }

        QString textstring =  pData[selectRow].getInfo();
        ui->textBrowser->setText(textstring.toUtf8().toHex(' '));

    }
}
