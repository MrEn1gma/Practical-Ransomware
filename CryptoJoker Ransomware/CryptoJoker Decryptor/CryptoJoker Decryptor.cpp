// CryptoJocker Decryptor.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <tchar.h>
#include <Windows.h>
#include <shlobj.h>
#include <filesystem>

namespace fs = std::filesystem;

void findKey(std::string enc_filename, std::string org_filename, int &key) {
    // OPEN ENCRYPTED FILE
    std::ifstream enc_data(enc_filename, std::ios::binary);
    enc_data.seekg(0, std::ios::end);
    size_t size_file = enc_data.tellg();
    enc_data.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf;
    buf.resize(size_file / sizeof(uint8_t));
    enc_data.read((char*)buf.data(), size_file);
    uint8_t* arrOfEncyptedFile = buf.data();
    //std::cout << size_file << std::endl;
    enc_data.close();

    // OPEN ORGINAL FILE
    std::ifstream enc_data1(org_filename, std::ios::binary);
    enc_data1.seekg(0, std::ios::end);
    size_t size_file1 = enc_data1.tellg();
    enc_data1.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf1;
    buf1.resize(size_file1 / sizeof(uint8_t));
    enc_data1.read((char*)buf1.data(), size_file1);
    uint8_t* arrOfEncyptedFile1 = buf1.data();
    //std::cout << size_file << std::endl;
    enc_data1.close();
    for (int i = 0; i < 1; i++)
    {
        key = arrOfEncyptedFile[i] - arrOfEncyptedFile1[i];             //TEST THE FIRST ELEMENT OF ARRAY
    }
    std::cout << "FOUND Key: " << key << std::endl;
    //std::cout << arrOfEncyptedFile;
}

void FindAllFiles(std::wstring FolderName, std::vector<std::wstring>& out)
{
    TCHAR path[MAX_PATH];
    std::wstring path_ = FolderName + L"\\*.*"; // or using L"\\" is OK
    std::wstring outstring;
    wcscpy_s(path, MAX_PATH, path_.c_str());
    WIN32_FIND_DATA findData;
    HANDLE hHandle = FindFirstFile(path, &findData);

    /*if (hHandle == INVALID_HANDLE_VALUE) {
        return TEXT("Error");
    }*/
    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Because of scan directory to successfull, there are list of "."and ".." that we don't want to display.
            // If string compare cFileName with "." and string compare cFileName with ".." then skip it
            if (_tcscmp(findData.cFileName, L".") && _tcscmp(findData.cFileName, L"..")) {
                // foldername \\ new folder name \\ new file
                FindAllFiles(FolderName + L"\\" + findData.cFileName, out);
            }
        }
        else {
            // Get file path using filesystem then we can get an extension
            // List extensions will be targeted
            fs::path filePath = FolderName + L"\\" + findData.cFileName;
            if (filePath.extension() == ".cryptojoker") {
                // Push elements to the last of vector
                out.push_back(FolderName + L"\\" + findData.cFileName);
            }
        }
    } while (FindNextFile(hHandle, &findData));

    /*DWORD dwError = GetLastError();
    if (dwError == ERROR_NO_MORE_FILES) {
        //exit(0);
    }*/
    FindClose(hHandle);
}

void decryptFiles(std::wstring target_file, int key) {
    std::wstring target_filepart;
    size_t ext = target_file.find_last_of(L".");
    if (ext != std::wstring::npos) {
        target_filepart = target_file.substr(0, ext);
    }
    fs::path filepath = target_filepart;
    if (filepath.extension() == ".fully") {
        std::ifstream enc_data(target_file, std::ios::binary);
        enc_data.seekg(0, std::ios::end);
        size_t size_file = enc_data.tellg();
        enc_data.seekg(0, std::ios::beg);
        std::vector<uint8_t> buf;
        buf.resize(size_file / sizeof(uint8_t));
        enc_data.read((char*)buf.data(), size_file);
        enc_data.close();
        //std::cout << size_file << std::endl;
        uint8_t* arrofDecryptedFile = buf.data();
        // DEFINE output array
        for (int i = 0; i < size_file; i++)
        {
            arrofDecryptedFile[i] = (arrofDecryptedFile[i] - key);
        }
        //std::cout << arrofDecryptedFile;
        size_t ext1 = target_filepart.find_last_of(L".");
        if (ext1 != std::wstring::npos) {
            target_filepart = target_filepart.substr(0, ext1);
        }
        std::ofstream outf(target_filepart, std::ios::binary);
        for (int j = 0; j < size_file; j++)
        {
            outf.write((char*)&arrofDecryptedFile[j], sizeof(uint8_t));
        }
        outf.close();
        std::wcout << "Saved file: " << target_filepart << std::endl;
        std::filesystem::remove(target_file);
    }
    else if (filepath.extension() == ".partially")
    {
        std::ifstream enc_data(target_file, std::ios::binary);
        enc_data.seekg(0, std::ios::end);
        size_t size_file = enc_data.tellg();
        enc_data.seekg(0, std::ios::beg);
        std::vector<uint8_t> buf;
        buf.resize(size_file / sizeof(uint8_t));
        enc_data.read((char*)buf.data(), size_file);
        enc_data.close();
        //std::cout << size_file << std::endl;
        uint8_t* arrofDecryptedFile = buf.data();
        if (size_file < 1024) {
            // DEFINE output array
            for (int i = 0; i < size_file; i++)
            {
                arrofDecryptedFile[i] = (arrofDecryptedFile[i] - key);
            }
        }
        else {
            // DEFINE output array
            for (int i = 0; i < 1024; i++)
            {
                arrofDecryptedFile[i] = (arrofDecryptedFile[i] - key);
            }
        }
        //std::cout << arrofDecryptedFile;
        size_t ext1 = target_filepart.find_last_of(L".");
        if (ext1 != std::wstring::npos) {
            target_filepart = target_filepart.substr(0, ext1);
        }
        std::ofstream outf(target_filepart, std::ios::binary);
        for (int j = 0; j < size_file; j++)
        {
            outf.write((char*)&arrofDecryptedFile[j], sizeof(uint8_t));
        }
        outf.close();
        std::wcout << "Saved file: " << target_filepart << std::endl;
        std::filesystem::remove(target_file);
    }
}

int main()
{
    int password_decryption = 0;
    do {
        std::cout << "\n---=== CryptoJoker Decrypter by MrEn1gma ===---\n" << std::endl;
        std::cout << "This decryptor now support these extensions: .fully.cryptojoker, .partially.cryptojoker" << std::endl;
        std::cout << "1. Recover key by using encrypted file and orginal file." << std::endl;
        std::cout << "2. Decrypt." << std::endl;
        std::cout << "3. Exit." << std::endl;
        int yourchoice;
        std::cout << "Your choice: ";
        std::cin >> yourchoice;

        std::string enc_filename, org_filename;
        std::wstring pathname;
        std::vector<std::wstring> out;

        switch (yourchoice)
        {
        case 1:
            std::cout << "Encrypted file: ";                  // CRACK.txt.fully.cryptojoker
            std::cin >> enc_filename;
            std::cout << "Orginal file: ";                    // CRACK.txt
            std::cin >> org_filename;
            findKey(enc_filename, org_filename, password_decryption);
            break;
        case 2: 
            if (password_decryption == 0) {                   // If user did not type the option 1
                std::cout << "Decryption key: ";
                std::cin >> password_decryption;
            }
            std::cout << "Enter the path of this directory that you want to decrypt: ";
            std::wcin >> pathname;
            std::wcout << L"Scanning directory: " << pathname << std::endl;
            FindAllFiles(pathname, out);
            std::wcout << "Count: " << out.size() << std::endl;
            for (int i = 0; i < out.size(); i++)
            {
                std::wcout << L"Decrypting: " << out[i] << std::endl;
                decryptFiles(out[i], password_decryption);
            }
            std::cout << "DONE !!!" << std::endl;
            break;

        case 3:
            ExitProcess(0);
        default:
            break;
        }
    } while (true);
    return 0;
}