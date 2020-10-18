import socket
import struct
import sys
import scapy.all as scapy
from scapy.layers import http
from ctypes import *

""" Asrın Utku Yagmur """


host = socket.gethostbyname(socket.gethostname())
""" işlenmemiş (ham) socket oluşturup , bind fonksiyonuyla genel arayüze bağlıyoruz"""
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

def paketlerial(s):
    data = ''
    try:
        data = s.recvfrom(65565)
    except TimeoutError:
        data = ''
    except:
        print("Hata Tespit Edildi: ")
        sys.exc_info()

    print(data[0])
    return data[0]


class IPHeader(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ubyte),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]

    def __new__(self, data = None):
        return self.from_buffer_copy(data)

    def __init__(self, data=None):

        """ 32 bitlik IPV4 adresini ?.?.?.? şekline çeviriyoruz"""
        self.kaynakip = socket.inet_ntoa(struct.pack("@I", self.src))
        self.hedefip = socket.inet_ntoa(struct.pack("@I", self.dst))

        self.protocols = {1:"ICMP", 6:"TCP", 17:"UDP"}

        try:
            self.protocol = self.protocols[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


def servisinturu(data):

    oncelik = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash", 4: "Flash override", 5: "CRITIC/ECP",
                  6: "Internetwork control", 7: "Network control"}
    delay = {0: "Normal delay", 1: "Yüksek delay"}
    cıktısuresi = {0: "Normal çıktı süresi", 1: "Yüksek çıktı süresi"}
    guvenırlık = {0: "Normal güvenirlik", 1: "Yüksek güvenirlik"}

    #   biti al ve sağa kaydır
    d = data & 0x10
    d >>= 4

    t = data & 0x8
    t >>= 3

    r = data & 0x4
    r >>= 2

    servisinturu = oncelik[data >> 5] +"- "+ delay[d] +"- "+ cıktısuresi[t] +"- "+ guvenırlık[r]

    return servisinturu


def bayraklar(data):
    flagr = {0: "0:Sabit bit"}
    flagdf = {0: "0:Paketin parçalanması gerekiyor", 1: "1:Paket parçalanmamalı"}
    flagmf = {0: "0:Paketin son parçalanması ", 1: "1:Paket daha fazla parçalanacak"}

    #   ilk biti al ve sağa kaydır
    r = data & 0x8000
    r >>= 15

    df = data & 0x4000
    df >>= 14

    mf = data & 0x2000
    mf >>= 13

    bayraklar = flagr[r] +"- "+ flagdf[df] +"- "+ flagmf[mf]
    return bayraklar

def baglanti():

    """ işlenmemiş (ham) socket oluşturup , bind fonksiyonuyla genel arayüze bağlıyoruz"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.bind((host, 0))

    """IP başlıklarını ekliyoruz"""
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    """ tüm paketleri alabileceğimiz bir moda geçiyoruz """
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    return sock

def idvesifresniffer(interface):

    scapy.sniff(iface = interface,store = False, prn = paketfiltreleme)


def paketfiltreleme(packets):

    if packets.haslayer(http.HTTPRequest):
        url = packets[http.HTTPRequest].Host + packets[http.HTTPRequest].Path

        if packets.haslayer(scapy.Raw):
            print("url :", url)
            print(packets[scapy.Raw])

        print("id ve sifre bilgisi yakalandı")
        exit(0)

def main():
    sniffer = baglanti()

    print("Cıkıs yapmak icin 0 \nPaket sniffer icin 1 \nid-sifre snifferi icin 2")
    secim =input()

    if(secim == "1"):
        print("Sniffer Başlıyor")
        while 1:
            try:
                """ henüz işlenmemiş paketleri alıyoruz """
                rawpack = paketlerial(sniffer)
                ipheader = IPHeader(rawpack[0:20])
                unpackeddata = struct.unpack('!BBHHHBBH4s4s', rawpack[:20])


                if(ipheader.protocol == "TCP" or ipheader.protocol == "IP" or ipheader.protocol == "UDP"):
                    print("hi")
                    """ IP protokol sürümü , geçerli sürüm 4 (IPV4)"""
                    versionihl = unpackeddata[0]
                    version = versionihl >> 4

                    """ Paketin önceliği, gecikmesi, güvenilirliği ve iletim hızı konularında bilgi verir"""
                    updservisinturu = unpackeddata[1]

                    """ Identification : ip paketlerini iletim sırasında diğer ip paketlerinden ayırır (iletim sırasında parçalanmaya karşı) 
                    aynı bilgiyi taşıyan tüm paketlere aynı id numarası verilir"""
                    updidentification = unpackeddata[3]

                    """Bayraklar : Parçalanma bilgisini tutar"""
                    updbayraklar = unpackeddata[4]

                    """ Fragment Offset : Bu 13 bit alan, parçanın orijinal parçalanmış IP paketindeki konumunu belirtir."""
                    updfragmentOffset = unpackeddata[4] & 0x1FFF

                    """ Bir IP paketinin yaşam süresini tutar ve paketlerin sonsuza kadar döngü yapmasını engeller."""
                    updpaketinyasamsuresi = unpackeddata[5]

                    """ Aktarım sırasında ip headerında herhangi bir hata oluşup oluşmadığını belirlemek için kullanılır."""
                    udpheaderkontrol = unpackeddata[7]

                    print("Kullanılan Protokol : "+ipheader.protocol +" | " +
                        " Hedef IP adresi : " + ipheader.kaynakip +" | " +
                        "Kaynak IP adresi :" + ipheader.hedefip +" | " +
                        "ID: " + str(hex(updidentification)) + " (" + str(updidentification) + ")" + " | " +
                        "Version: " + str(version)+" | " +
                        "Type of Service: " + servisinturu(updservisinturu)+" | " +
                        "Bayraklar : " + bayraklar(updbayraklar)+" | " +
                        "Paketin Yasam Suresi :" + str(updpaketinyasamsuresi) +" | " +
                        "Header Checksum : " + str(udpheaderkontrol)
                        )
                    print("\n-----------------\n")
            except Exception as ex:
                print(ex)

    elif(secim == "2"):
        print("id-sifre bilgisini iceren paket bekleniyor.....\n")
        interface = 'Realtek PCIe GbE Family Controller'
        idvesifresniffer(interface)

    elif(secim == "3"):
        print("Cıkıs yapılıyor")
        exit(0)

main()