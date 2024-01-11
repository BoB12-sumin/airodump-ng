#include <pcap.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ifaddrs.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <array>
#include <thread>
#include <chrono>
#include "radiotab.h"

using namespace std;

struct dot11
{
    u_int8_t it_version; /* set to 0 */
    u_int8_t it_pad;
    u_int16_t it_len;     /* entire length */
    u_int32_t it_present; /* fields present */
} __attribute__((__packed__));

void print_dot11(struct dot11 *my_struct)
{
    printf("it_version: %u\n", my_struct->it_version);
    printf("it_pad: %u\n", my_struct->it_pad);
    printf("it_len: %u\n", my_struct->it_len);
    printf("it_present: %u\n", my_struct->it_present);
}

void usage()
{
    printf("syntax: airo-mon <interface> \n");
    printf("sample: airo-mon wlan0\n");
}

void parse_radiotap_header(struct dot11 *header, size_t length)
{
    // Check version
    if (header->it_version != 0)
    {
        printf("packet's version must be 0 \n");
        return;
    }

    uint32_t present = header->it_present;
    size_t offset = sizeof(dot11);

    while (offset < length)
    {
        if (present & (1 << IEEE80211_RADIOTAP_TSFT))
        {
            // TSFT 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_FLAGS))
        {
            // FLAGS 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_RATE))
        {
            // RATE 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_CHANNEL))
        {
            // CHANNEL 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_FHSS))
        {
            // FHSS 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL))
        {
            // DBM_ANTSIGNAL 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_DBM_ANTNOISE))
        {
            // DBM_ANTNOISE 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_LOCK_QUALITY))
        {
            // LOCK_QUALITY 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_TX_ATTENUATION))
        {
            // TX_ATTENUATION 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_DB_TX_ATTENUATION))
        {
            // DB_TX_ATTENUATION 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_DBM_TX_POWER))
        {
            // DBM_TX_POWER 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_ANTENNA))
        {
            // ANTENNA 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_DB_ANTSIGNAL))
        {
            // DB_ANTSIGNAL 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_DB_ANTNOISE))
        {
            // DB_ANTNOISE 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_RX_FLAGS))
        {
            // RX_FLAGS 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_TX_FLAGS))
        {
            // TX_FLAGS 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_RTS_RETRIES))
        {
            // RTS_RETRIES 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_DATA_RETRIES))
        {
            // DATA_RETRIES 필드 처리
        }
        // 18번 필드는 정의되지 않았으므로 생략
        if (present & (1 << IEEE80211_RADIOTAP_MCS))
        {
            // MCS 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_AMPDU_STATUS))
        {
            // AMPDU_STATUS 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_VHT))
        {
            // VHT 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_TIMESTAMP))
        {
            // TIMESTAMP 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE))
        {
            // RADIOTAP_NAMESPACE 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_VENDOR_NAMESPACE))
        {
            // VENDOR_NAMESPACE 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_EXT))
        {
            // EXT 필드 처리 및 다음 it_present 확인
            present = *reinterpret_cast<const uint32_t *>(header + offset);
            offset += sizeof(uint32_t);
        }
        else
        {
            break;
        }
    }

    if (length < offset + 16)
    {
        printf("Packet too short for BSSID\n");
        return;
    }

    const uint8_t *frame_ptr = reinterpret_cast<const uint8_t *>(header) + offset; // beacon frame
    const uint8_t *bssid_ptr = frame_ptr + 16;                                     // 802.11 헤더로부터 16바이트 뒤

    printf("BSSID: ");
    for (int i = 0; i < 6; ++i)
    {
        printf("%02x", bssid_ptr[i]);
        if (i < 5)
            printf(":");
    }
    printf("\n");

    // beacon frame

    // 16bytes 뒤에 beacon frame의 BSSID 존재함.
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    struct pcap_pkthdr *header;
    const uint8_t *packet;
    u_char *reply1 = nullptr;

    while (true)
    {
        int ret = pcap_next_ex(handle, &header, &packet);
        if (ret == 0)
        {
            printf("Timeout, no packet received\n");
            continue;
        }
        if (ret == -1 || ret == -2)
        {
            // Error or EOF, break the loop
            fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
            break;
        }

        // reply1 = reinterpret_cast<>(const_cast<u_char*>(reply_packet1));

        printf("%u bytes captured\n", header->caplen); // packet's lengt

        struct dot11 *radiotap_hdr = (struct dot11 *)packet;

        parse_radiotap_header(radiotap_hdr, header->caplen);

        print_dot11(radiotap_hdr);

        // for (int i = 0; i < (header->caplen); i++)
        // {
        //     printf("%02x ", packet[i]);
        // }

        // printf("\n");
    }

    return 0;
}