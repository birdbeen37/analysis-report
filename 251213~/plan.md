1) Week 1 — 전체 작업 목록 (Full Breakdown)
🎯 [A] Malware Analysis — Week 1 목표: “정적 + 동적 분석 전체 흐름 복습용 분석 1회”
🔹 1. 샘플 선정

내가 아래 추천한 샘플 중 1개 선택

PE32 기반 + 난이도 Easy~Medium

🔹 2. 정적 분석 (Static Analysis)

세부 단계:

파일 기본 정보 수집

PE header / Section / Hash(SHA256, MD5) / Compile timestamp

Strings 추출 및 분류

URL / IP / Mutex / Registry key / API keyword 분류

Imports / Exports 분석

행동 추정 포인트 표시 (e.g., WinInet 사용 여부, Process Injection 관련 API 등)

Section 구조 분석

UPX 여부, packed 여부 판단

수상한 리소스/데이터 블록 확인

간단한 Unpacking 시도 (UPX → upx -d / 복잡한 건 Week 3로 미룸)

🔹 3. 동적 분석 (Dynamic Analysis)

실행 전 스냅샷 생성

Process Monitor, Process Explorer, Wireshark 설정

동적 이벤트 수집

File I/O / Registry / Process Injection / Network 트래픽

Network 행동 기록

Domain, URL, TLS fingerprint, C2 handshake 여부

흔히 나오는 Anti-VM 동작이 있는지 관찰

Behavior 요약 정리

🔹 4. 최종 리포트 작성

리포트 구성(Week 1 템플릿 버전):

Overview

Basic Information

Static Analysis

Dynamic Analysis

Identified Malicious Behavior

MITRE ATT&CK Mapping

IoC summary

결론(이 샘플이 하는 핵심 행동)

➡ 이 리포트는 GitHub 공개 버전 + Notion 내부 상세 버전 2개로 관리

🎯 [B] Offensive Research — Week 1 주제: “Process Injection Basics”

Week 1 연구 주제는 기초 다지기에 최적화된 Process Injection 기본 유형 정리
(너의 진로가 Offsec & Malware dev 중심이기 때문에, 기본을 solid하게 잡는게 핵심)

🔹 1. 학습 범위

Classic Injection 개념 정리

WriteProcessMemory + CreateRemoteThread

LoadLibraryA 인젝션

APC Injection 기본 개념

인젝션 시 Detection Point

Sysmon Event ID 8/10/11

EDR Hooking 포인트 (NtWriteVirtualMemory, NtQueueApcThread 등)

🔹 2. 할 일 (연구 정리)

각 인젝션 방식별

개념

API call flow

장단점

탐지 포인트

노션에 분석 페이지 생성

GitHub wiki 또는 Markdown으로 “Process Injection Week 1 Summary” 업로드

🎯 [C] PoC Development — Week 1 목표: “XOR Decoder PoC (기본기 프로젝트)”

너가 이미 XOR + zlib decoder를 많이 다뤘기 때문에 Week 1 PoC 목표는 가볍게 간다.

🔹 1. 구현 목표

문자열 또는 파일에 대해

단일-byte XOR 또는 multi-byte XOR

키를 입력으로 받아 복호화 수행

C 기반 또는 C++ 기반 (너 C도 잘함)

🔹 2. 최소 구현 기능

argv로 key / input 파일 / output 파일 받기

XOR decode 수행

decode 결과를 stdout + 파일로 출력

잘못된 키로 디코딩 시 오류 메시지 제공

🔹 3. 코드 스켈레톤 제공
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void xor_decode(unsigned char *data, size_t len, const char *key) {
    size_t key_len = strlen(key);
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <key> <input> <output>\n", argv[0]);
        return 1;
    }

    const char *key = argv[1];
    const char *infile = argv[2];
    const char *outfile = argv[3];

    FILE *f = fopen(infile, "rb");
    if (!f) { perror("input"); return 1; }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *buf = malloc(size);
    fread(buf, 1, size, f);
    fclose(f);

    xor_decode(buf, size, key);

    FILE *o = fopen(outfile, "wb");
    fwrite(buf, 1, size, o);
    fclose(o);

    free(buf);

    printf("[+] Decoding complete.\n");
    return 0;
}