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
#include <vector>
#include <string>
#include <utility>
#include <cstring>
#include <map>
#include <iomanip>

using namespace std;

struct dot11
{
    u_int8_t it_version; /* set to 0 */
    u_int8_t it_pad;
    u_int16_t it_len;     /* entire length */
    u_int32_t it_present; /* fields present */
} __attribute__((__packed__));

struct BSSID_Info
{
    int pwr; // pwr
    int channel;
    int beacons;
    string essid;
};

struct RadiotapInfo
{
    int rssi;
    int channel;
    const uint8_t *bssid_ptr;
    string essid;
};

struct ProbeReqInfo
{
    string source_mac;
};

struct ProbeResInfo
{
    string source_mac;
    string dest_mac;
};
// BSSID를 key로 사용하는 map 생성
map<string, BSSID_Info> bssid_map;

vector<string> probe_requests; // 모든 프로브 요청을 저장하는 벡터
vector<pair<string, string>> station_info;

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

bool check_beacon_frame(const uint8_t *frame_ptr, size_t length)
{
    if (length < 2)
    {
        return false;
    }

    const uint16_t *type_sub_type_field = reinterpret_cast<const uint16_t *>(frame_ptr);
    uint16_t type_sub_type = ntohs(*type_sub_type_field); // 네트워크 바이트 순서를 호스트 바이트 순서로 변환

    // Beacon frame의 타입 및 서브타입 값은 0x8000
    return type_sub_type == 0x8000;
}

bool check_probe_request_frame(const uint8_t *frame_ptr, size_t length)
{
    if (length < 2)
    {
        return false;
    }

    const uint16_t *type_sub_type_field = reinterpret_cast<const uint16_t *>(frame_ptr);
    uint16_t type_sub_type = ntohs(*type_sub_type_field);

    return type_sub_type == 0x4000;
}

bool check_probe_response_frame(const uint8_t *frame_ptr, size_t length)
{
    if (length < 2)
    {
        return false;
    }

    const uint16_t *type_sub_type_field = reinterpret_cast<const uint16_t *>(frame_ptr);
    uint16_t type_sub_type = ntohs(*type_sub_type_field);

    return type_sub_type == 0x5000;
}

void adjust_offset_for_boundary(size_t &offset, size_t field_size)
{
    if (field_size % 2 == 0)
    {
        offset = (offset + 1) & ~1; // 2바이트 경계에 맞추기
    }
}
string bssid_to_string(const uint8_t *bssid)
{
    stringstream ss;
    for (int i = 0; i < 6; ++i)
    {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(bssid[i]);
        if (i < 5)
            ss << ":";
    }
    return ss.str();
}

void process_beacon_frame(const RadiotapInfo &info)
{
    string bssid_str = bssid_to_string(info.bssid_ptr); // BSSID를 string으로 변환하는 함수 필요

    // BSSID 정보 업데이트
    if (bssid_map.find(bssid_str) == bssid_map.end())
    {
        // BSSID가 map에 없으면 새로 추가
        bssid_map[bssid_str] = {info.rssi, info.channel, 1, info.essid};
    }
    else
    {
        // 이미 존재하는 BSSID면 정보 업데이트
        bssid_map[bssid_str].pwr = info.rssi;
        bssid_map[bssid_str].channel = info.channel;
        bssid_map[bssid_str].beacons++;
        bssid_map[bssid_str].essid = info.essid;
    }

    // 데이터 출력
    puts("BSSID\t\t\tPWR\tBeacons\t\tChannel\t\tESSID");
    for (const auto &pair : bssid_map)
    {
        const BSSID_Info &info = pair.second;
        printf("%s\t%d\t%d\t\t%d\t\t%s\n", pair.first.c_str(), info.pwr, info.beacons, info.channel, info.essid.c_str());
    }
}

RadiotapInfo parse_radiotap_header(struct dot11 *header, size_t length)
{
    RadiotapInfo info;
    // Check version
    if (header->it_version != 0)
    {
        printf("packet's version must be 0 \n");
        return RadiotapInfo();
        ;
    }

    uint32_t present = header->it_present;
    int radiolength = header->it_len;
    size_t offset = sizeof(dot11);
    vector<pair<int, size_t>> radiotap_fields;

    while (offset < radiolength)
    {
        if (present & (1 << IEEE80211_RADIOTAP_TSFT))
        {
            // TSFT 필드 처리
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_TSFT, sizeof(uint64_t))); // 예시: TSFT는 8바이트
            // offset += sizeof(uint64_t);
        }
        if (present & (1 << IEEE80211_RADIOTAP_FLAGS))
        {
            // FLAGS 필드 처리, 1byte
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_FLAGS, sizeof(uint8_t)));
            // offset += sizeof(uint8_t);
        }
        if (present & (1 << IEEE80211_RADIOTAP_RATE))
        {
            // RATE 필드 처리, 1byte
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_RATE, sizeof(uint8_t)));
        }
        if (present & (1 << IEEE80211_RADIOTAP_CHANNEL))
        {
            // CHANNEL 필드 처리, 2byte
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_CHANNEL, sizeof(int32_t)));
        }
        if (present & (1 << IEEE80211_RADIOTAP_FHSS))
        {
            // FHSS 필드 처리
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_FHSS, sizeof(uint16_t)));
        }
        if (present & (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL))
        {
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_DBM_ANTSIGNAL, sizeof(int8_t)));
            // offset += sizeof(int8_t);
        }
        if (present & (1 << IEEE80211_RADIOTAP_DBM_ANTNOISE))
        {
            // DBM_ANTNOISE 필드 처리
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_DBM_ANTNOISE, sizeof(int8_t)));
        }
        if (present & (1 << IEEE80211_RADIOTAP_LOCK_QUALITY))
        {
            // LOCK_QUALITY 필드 처리
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_LOCK_QUALITY, sizeof(int16_t)));
        }
        if (present & (1 << IEEE80211_RADIOTAP_TX_ATTENUATION))
        {
            // TX_ATTENUATION 필드 처리
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_TX_ATTENUATION, sizeof(int16_t)));
        }
        if (present & (1 << IEEE80211_RADIOTAP_DB_TX_ATTENUATION))
        {
            // DB_TX_ATTENUATION 필드 처리
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_DB_TX_ATTENUATION, sizeof(int16_t)));
        }
        if (present & (1 << IEEE80211_RADIOTAP_DBM_TX_POWER))
        {
            // DBM_TX_POWER 필드 처리
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_DBM_TX_POWER, sizeof(int8_t)));
        }
        if (present & (1 << IEEE80211_RADIOTAP_ANTENNA))
        {
            // ANTENNA 필드 처리
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_ANTENNA, sizeof(int8_t)));
        }
        if (present & (1 << IEEE80211_RADIOTAP_DB_ANTSIGNAL))
        {
            // DB_ANTSIGNAL 필드 처리
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_DB_ANTSIGNAL, sizeof(int8_t)));
        }
        if (present & (1 << IEEE80211_RADIOTAP_DB_ANTNOISE))
        {
            // DB_ANTNOISE 필드 처리
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_DB_ANTNOISE, sizeof(int8_t)));
        }
        if (present & (1 << IEEE80211_RADIOTAP_RX_FLAGS))
        {
            // RX_FLAGS 필드 처리, 2byte
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_RX_FLAGS, sizeof(int16_t)));
        }
        if (present & (1 << IEEE80211_RADIOTAP_TX_FLAGS))
        {
            // TX_FLAGS 필드 처리, 2byte
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_TX_FLAGS, sizeof(int16_t)));
        }
        if (present & (1 << IEEE80211_RADIOTAP_RTS_RETRIES))
        {
            // RTS_RETRIES 필드 처리
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_RTS_RETRIES, sizeof(int8_t)));
        }
        if (present & (1 << IEEE80211_RADIOTAP_DATA_RETRIES))
        {
            // DATA_RETRIES 필드 처리
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_DATA_RETRIES, sizeof(int8_t)));
        }
        // 18번 필드는 정의되지 않았으므로 생략
        if (present & (1 << IEEE80211_RADIOTAP_MCS))
        {
            // MCS 필드 처리
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_MCS, sizeof(int8_t) * 3));
        }
        if (present & (1 << IEEE80211_RADIOTAP_AMPDU_STATUS))
        {
            // AMPDU_STATUS 필드 처리
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_AMPDU_STATUS, sizeof(int64_t)));
        }
        if (present & (1 << IEEE80211_RADIOTAP_VHT))
        {
            // VHT 필드 처리
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_VHT, sizeof(int8_t) * 12));
        }
        if (present & (1 << IEEE80211_RADIOTAP_TIMESTAMP))
        {
            // TIMESTAMP 필드 처리
            radiotap_fields.push_back(make_pair(IEEE80211_RADIOTAP_TIMESTAMP, sizeof(int8_t) * 12));
        }
        if (present & (1 << IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE))
        {
            // RADIOTAP_NAMESPACE 필드 처리, 0byste
        }
        if (present & (1 << IEEE80211_RADIOTAP_VENDOR_NAMESPACE))
        {
            // VENDOR_NAMESPACE 필드 처리
        }
        if (present & (1 << IEEE80211_RADIOTAP_EXT))
        {
            // EXT 필드 처리 및 다음 it_present 확인 4byte
            present = *reinterpret_cast<const uint32_t *>(reinterpret_cast<const u_char *>(header) + offset);
            // 다음 it_present 값 출력
            printf("Next it_present: 0x%08x\n", present);
            offset += sizeof(uint32_t);
        }
        else
        {
            break;
        }
    }

    // printf("Radiotap Fields:\n");
    // for (const auto &field : radiotap_fields)
    // {
    //     printf("Field Type: %d, Size: %zu bytes\n", field.first, field.second);
    // }
    // printf("offset:%d\n", offset);

    // radiotap_fields여기서 offset 부터 시작하여 radiotap_fields여기서를 처리하여 attena signal을 읽는 코드를 추가할 것
    int8_t rssi = 0;
    int8_t antenna_noise = 0;
    bool rssi_updated = false;
    uint16_t channel_frequency, channel_flags;
    int channel;
    // 필드 처리 루프
    for (const auto &field : radiotap_fields)
    {
        adjust_offset_for_boundary(offset, field.second);

        switch (field.first)
        {
        case IEEE80211_RADIOTAP_TSFT:

            break;
        case IEEE80211_RADIOTAP_FLAGS:

            break;
        case IEEE80211_RADIOTAP_RATE:

            break;
        case IEEE80211_RADIOTAP_CHANNEL:

            memcpy(&channel_frequency, reinterpret_cast<const uint8_t *>(header) + offset, sizeof(uint16_t));
            memcpy(&channel_flags, reinterpret_cast<const uint8_t *>(header) + offset + sizeof(uint16_t), sizeof(uint16_t));

            channel_frequency = le16toh(channel_frequency); // 주파수 변환
            channel_flags = le16toh(channel_flags);         // 채널 플래그 변환

            if (channel_frequency >= 2412 && channel_frequency <= 2484)
            {
                // 2.4GHz 대역
                channel = (channel_frequency - 2412) / 5 + 1;
            }
            else if (channel_frequency >= 5000)
            {
                // 5GHz 대역
                channel = (channel_frequency - 5000) / 5;
            }
            else
            {
                // 알 수 없는 주파수 대역
                channel = -1;
            }
            // 채널 번호 사용

            // printf("channel: %d\n", channel);
            info.channel = channel;

            break;
        case IEEE80211_RADIOTAP_FHSS:

            break;
        case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
            rssi = *(reinterpret_cast<const int8_t *>(header) + offset);
            // printf("Antenna Signal (RSSI): %d dBm\n", rssi);
            rssi_updated = true; // 신호 강도 업데이트
            break;
        case IEEE80211_RADIOTAP_DBM_ANTNOISE:
            // DBM_ANTNOISE 필드 처리

            break;
        case IEEE80211_RADIOTAP_LOCK_QUALITY:
            // LOCK_QUALITY 필드 처리

            break;
        case IEEE80211_RADIOTAP_TX_ATTENUATION:
            // TX_ATTENUATION 필드 처리

            break;
        case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
            // DB_TX_ATTENUATION 필드 처리

            break;
        case IEEE80211_RADIOTAP_DBM_TX_POWER:
            // DBM_TX_POWER 필드 처리

            break;
        case IEEE80211_RADIOTAP_ANTENNA:
            // ANTENNA 필드 처리

            break;
        case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
            // DB_ANTSIGNAL 필드 처리

            break;
        case IEEE80211_RADIOTAP_DB_ANTNOISE:
            // DB_ANTNOISE 필드 처리

            break;
        case IEEE80211_RADIOTAP_RX_FLAGS:

            break;
        case IEEE80211_RADIOTAP_TX_FLAGS:

            break;
        case IEEE80211_RADIOTAP_RTS_RETRIES:

            break;
        case IEEE80211_RADIOTAP_DATA_RETRIES:

            break;
        // 18번 필드는 정의되지 않았으므로 생략
        case IEEE80211_RADIOTAP_MCS:

            break;
        case IEEE80211_RADIOTAP_AMPDU_STATUS:
            // AMPDU_STATUS 필드 처리

            break;
        case IEEE80211_RADIOTAP_VHT:
            // VHT 필드 처리

            break;
        case IEEE80211_RADIOTAP_TIMESTAMP:
            // TIMESTAMP 필드 처리

            break;
            // case IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE:
            //     // RADIOTAP_NAMESPACE 필드 처리
            //     break;
            // case IEEE80211_RADIOTAP_VENDOR_NAMESPACE:
            //     // VENDOR_NAMESPACE 필드 처리
            //     break;
            // case IEEE80211_RADIOTAP_EXT:
            //     // EXT 필드 처리 및 다음 it_present 확인
            //     // present = *reinterpret_cast<const uint32_t *>(reinterpret_cast<const u_char *>(header) + offset);
            //     // offset += sizeof(uint32_t);
            // break;
        default:
            break;
        }
        offset += field.second;

        if (rssi_updated)
        {
            int8_t final_rssi = rssi - antenna_noise; // 노이즈가 없으면 0으로 가정
            // printf("Final Antenna Signal (RSSI): %d dBm\n", final_rssi);
            info.rssi = final_rssi;
            rssi_updated = false;
            antenna_noise = 0;
        }
    }

    if (length < offset + 16)
    {
        printf("Packet too short for BSSID\n");
        return RadiotapInfo();
    }
    // printf("offset1: %d\n", offset);

    const uint8_t *frame_ptr = reinterpret_cast<const uint8_t *>(header) + radiolength; // beacon frame
    const uint8_t *bssid_ptr = frame_ptr + 16;

    info.bssid_ptr = bssid_ptr;

    const size_t ieee80211_header_length = 24;

    // 비콘 프레임 페이로드 시작점
    const uint8_t *frame_payload_ptr = reinterpret_cast<const uint8_t *>(header) + radiolength + ieee80211_header_length;
    const uint8_t *tagged_ptr = frame_payload_ptr;

    const uint8_t *essid_ptr = reinterpret_cast<const uint8_t *>(tagged_ptr) + 12;
    uint8_t essid_pkt = *essid_ptr;

    const uint8_t *essid_len_ptr = reinterpret_cast<const uint8_t *>(essid_ptr) + 1;
    uint8_t essid_len = *essid_len_ptr;

    const uint8_t *essid_content_ptr = reinterpret_cast<const uint8_t *>(essid_ptr) + 2;
    uint8_t essid_content = *essid_content_ptr;

    string essid;
    for (int i = 0; i < essid_len; ++i)
    {
        essid += static_cast<char>(essid_content_ptr[i]);
    }

    info.essid = essid;

    return info;
}

ProbeReqInfo parse_probe_req_header(struct dot11 *header, size_t length)
{
    ProbeReqInfo info;
    if (header->it_version != 0)
    {
        printf("packet's version must be 0 \n");
        return ProbeReqInfo();
    }

    int radiolength = header->it_len;
    const size_t mac_offset = radiolength + 10; // 수정: radiolength + IEEE80211 헤더 길이 (24) - 14 (MAC 주소 위치)

    if (length < mac_offset + sizeof(uint8_t) * 6)
    {
        printf("Packet too short for source MAC\n");
        return ProbeReqInfo();
    }

    const uint8_t *frame_ptr = reinterpret_cast<const uint8_t *>(header) + mac_offset;
    info.source_mac = bssid_to_string(frame_ptr);

    return info;
}

ProbeResInfo parse_probe_res_header(struct dot11 *header, size_t length)
{
    ProbeResInfo info;
    if (header->it_version != 0)
    {
        printf("packet's version must be 0 \n");
        return ProbeResInfo();
    }

    int radiolength = header->it_len;
    const size_t source_mac_offset = radiolength + 10; // Source MAC address offset
    const size_t dest_mac_offset = radiolength + 4;    // Destination MAC address offset

    if (length < source_mac_offset + 6)
    {
        printf("Packet too short for source MAC\n");
        return ProbeResInfo();
    }
    const uint8_t *source_mac_ptr = reinterpret_cast<const uint8_t *>(header) + source_mac_offset;
    if (length < dest_mac_offset + 6)
    {
        printf("Packet too short for destination MAC\n");
        return ProbeResInfo();
    }

    const uint8_t *dest_mac_ptr = reinterpret_cast<const uint8_t *>(header) + dest_mac_offset;
    info.source_mac = bssid_to_string(source_mac_ptr);
    info.dest_mac = bssid_to_string(dest_mac_ptr);
    return info;
}

bool isDuplicate(const vector<pair<string, string>> &station_info, const string &reqMac, const string &resMac)
{
    for (const auto &info : station_info)
    {
        if (info.first == reqMac && info.second == resMac)
        {
            return true;
        }
    }
    return false;
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
    // pcap_t *handle = pcap_open_offline("./pcapdir/beacon-a2000ua-testap5g.pcap", errbuf);
    // pcap_t *handle = pcap_open_offline("./pcapdir/dot11-sample.pcap", errbuf);

    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    struct pcap_pkthdr *header;
    const uint8_t *packet;
    u_char *reply1 = nullptr;

    ProbeReqInfo station_mac_info;
    ProbeResInfo station_bssid_info;
    RadiotapInfo info;

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

        struct dot11 *radiotap_hdr = (struct dot11 *)packet;
        const size_t ieee80211_header_length = 24;

        if (check_beacon_frame(reinterpret_cast<const uint8_t *>(radiotap_hdr) + (radiotap_hdr->it_len), header->caplen - (radiotap_hdr->it_len)))
        {
            info = parse_radiotap_header(radiotap_hdr, header->caplen);
        }
        else if (check_probe_request_frame(reinterpret_cast<const uint8_t *>(radiotap_hdr) + (radiotap_hdr->it_len), header->caplen - (radiotap_hdr->it_len)))
        {
            station_mac_info = parse_probe_req_header(radiotap_hdr, header->caplen);
            probe_requests.push_back(station_mac_info.source_mac); // 프로브 요청 MAC 주소 저장
        }
        else if (check_probe_response_frame(reinterpret_cast<const uint8_t *>(radiotap_hdr) + (radiotap_hdr->it_len), header->caplen - (radiotap_hdr->it_len)))
        {
            station_bssid_info = parse_probe_res_header(radiotap_hdr, header->caplen);
            for (const auto &reqMac : probe_requests)
            {
                if (reqMac == station_bssid_info.dest_mac && !isDuplicate(station_info, station_bssid_info.source_mac, reqMac))
                {
                    station_info.push_back(make_pair(station_bssid_info.source_mac, reqMac)); // 일치하는 요청-응답 쌍 저장
                    break;
                }
            }
        }

        else
        {
            continue;
        }

        cout << "\033[2J\033[1;1H";

        process_beacon_frame(info);

        puts("\nBSSID\t\t\tSTATION");
        for (const auto &info : station_info)
        {
            printf("%s\t%s\n", info.first.c_str(), info.second.c_str());
        }
    }

    return 0;
}