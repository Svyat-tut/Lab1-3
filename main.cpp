
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#include <fstream>
#include <vector>
#include <cwchar>
#include <cstring>
#include <string>
#include "resource.h"

#define MAXNAME     20
#define MAXPASS     21
#define ADMIN_NAME  L"ADMIN"
#define MAX_TRIES   3

struct Account
{
    wchar_t UserName[MAXNAME];
    int     PassLen;
    wchar_t UserPass[MAXPASS];
    bool    Block;
    bool    Restrict;
};

static HINSTANCE g_hInst;
static Account   g_cur;
static bool      g_admin = false;
static bool      g_logged = false;

static bool CheckPassword(const wchar_t* s)
{
    bool digit = false, punct = false;
    for (; *s; ++s)
    {
        if (*s >= L'0' && *s <= L'9') digit = true;

        if (wcschr(L".,-:;!?()\"", *s)) punct = true;
    }
    return digit && punct;
}

static int FindUser(const std::vector<Account>& v, const wchar_t* name)
{
    for (size_t i = 0; i < v.size(); ++i)
        if (wcscmp(v[i].UserName, name) == 0) return (int)i;
    return -1;
}

#define ENCFILE      L"security.enc"
#define ALG_HASH     CALG_MD2
#define ALG_CIPHER   CALG_RC2
#define CIPHER_MODE  CRYPT_MODE_CFB
#define KEY_FLAGS    (CRYPT_EXPORTABLE | CRYPT_CREATE_SALT)
#define IV_LEN       8
#define MAXPH        64

static std::vector<Account> g_db;
static wchar_t g_pass[MAXPH];
static bool    g_loaded = false;

static bool AcquireProv(HCRYPTPROV* p)
{
    if (CryptAcquireContextW(p, NULL, NULL, PROV_RSA_FULL, 0)) return true;
    if (GetLastError() == (DWORD)NTE_BAD_KEYSET)
        return CryptAcquireContextW(p, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET) != FALSE;
    return false;
}

static bool MakeKey(HCRYPTPROV prov, const wchar_t* pass, DWORD flags, HCRYPTKEY* key)
{
    HCRYPTHASH h = 0;
    if (!CryptCreateHash(prov, ALG_HASH, 0, 0, &h)) return false;
    bool ok = CryptHashData(h, (const BYTE*)pass, (DWORD)(wcslen(pass) * sizeof(wchar_t)), 0) &&
              CryptDeriveKey(prov, ALG_CIPHER, h, flags, key);
    CryptDestroyHash(h);
    return ok;
}

static bool EncryptDb(const std::vector<Account>& v, const wchar_t* pass)
{
    HCRYPTPROV prov = 0;
    HCRYPTKEY  key = 0;
    bool ok = false;
    DWORD plain = (DWORD)(v.size() * sizeof(Account));
    std::vector<BYTE> buf(plain + 16);
    if (plain) memcpy(&buf[0], &v[0], plain);
    DWORD len = plain;
    BYTE  salt[256];
    DWORD saltLen = sizeof(salt);
    BYTE  iv[IV_LEN];
    DWORD mode = CIPHER_MODE;

    if (AcquireProv(&prov) && MakeKey(prov, pass, KEY_FLAGS, &key))
    {
        if (!CryptGetKeyParam(key, KP_SALT, salt, &saltLen, 0)) saltLen = 0;
        if (saltLen > 255) saltLen = 0;
        if (CryptGenRandom(prov, IV_LEN, iv) &&
            CryptSetKeyParam(key, KP_MODE, (BYTE*)&mode, 0) &&
            CryptSetKeyParam(key, KP_IV, iv, 0) &&
            CryptEncrypt(key, 0, TRUE, 0, &buf[0], &len, (DWORD)buf.size()))
        {
            const wchar_t* tmp = L"security.enc.tmp";
            {
                std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
                BYTE sl = (BYTE)saltLen;
                f.write((const char*)&sl, 1);
                f.write((const char*)salt, saltLen);
                f.write((const char*)iv, IV_LEN);
                f.write((const char*)&buf[0], len);
                ok = f.good();
            }
            if (ok) ok = MoveFileExW(tmp, ENCFILE, MOVEFILE_REPLACE_EXISTING) != FALSE;
            else DeleteFileW(tmp);
        }
    }
    if (key) CryptDestroyKey(key);
    if (prov) CryptReleaseContext(prov, 0);
    SecureZeroMemory(&buf[0], buf.size());
    return ok;
}

static bool DecryptDb(std::vector<Account>& out, const wchar_t* pass)
{
    std::vector<BYTE> all;
    {
        std::ifstream f(ENCFILE, std::ios::binary);
        if (!f) return false;
        f.seekg(0, std::ios::end);
        std::streamoff n = f.tellg();
        if (n <= 0 || n > 16 * 1024 * 1024) return false;
        all.resize((size_t)n);
        f.seekg(0, std::ios::beg);
        f.read((char*)&all[0], (std::streamsize)n);
        if (!f) return false;
    }
    size_t saltLen = all[0];
    if (all.size() < 1 + saltLen + IV_LEN + 8) return false;
    const BYTE* salt = &all[1];
    const BYTE* iv = &all[1 + saltLen];
    size_t hdr = 1 + saltLen + IV_LEN;
    std::vector<BYTE> data(all.begin() + hdr, all.end());
    DWORD len = (DWORD)data.size();
    DWORD mode = CIPHER_MODE;

    HCRYPTPROV prov = 0;
    HCRYPTKEY  key = 0;
    bool ok = false;
    if (AcquireProv(&prov) && MakeKey(prov, pass, CRYPT_EXPORTABLE, &key))
    {
        bool p = true;
        if (saltLen > 0) p = CryptSetKeyParam(key, KP_SALT, (BYTE*)salt, 0) != FALSE;
        if (p && CryptSetKeyParam(key, KP_MODE, (BYTE*)&mode, 0) &&
            CryptSetKeyParam(key, KP_IV, (BYTE*)iv, 0) &&
            CryptDecrypt(key, 0, TRUE, 0, &data[0], &len) &&
            len > 0 && len % sizeof(Account) == 0)
        {
            out.resize(len / sizeof(Account));
            memcpy(&out[0], &data[0], len);
            for (size_t i = 0; i < out.size(); ++i)
            {
                out[i].UserName[MAXNAME - 1] = 0;
                out[i].UserPass[MAXPASS - 1] = 0;
            }
            ok = FindUser(out, ADMIN_NAME) >= 0;
            if (!ok) out.clear();
        }
    }
    if (key) CryptDestroyKey(key);
    if (prov) CryptReleaseContext(prov, 0);
    SecureZeroMemory(&data[0], data.size());
    SecureZeroMemory(&all[0], all.size());
    return ok;
}

static bool LoadAll(std::vector<Account>& v)
{
    v = g_db;
    return true;
}

static bool SaveAll(const std::vector<Account>& v)
{
    g_db = v;
    return EncryptDb(g_db, g_pass);
}

struct LoginData { wchar_t name[MAXNAME]; wchar_t pass[MAXPASS]; };

static INT_PTR CALLBACK LoginProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_INITDIALOG:
        SetWindowLongPtrW(h, DWLP_USER, lp);
        SendDlgItemMessageW(h, IDC_LOGIN_NAME, EM_LIMITTEXT, MAXNAME - 1, 0);
        SendDlgItemMessageW(h, IDC_LOGIN_PASS, EM_LIMITTEXT, MAXPASS - 1, 0);

        SendDlgItemMessageW(h, IDC_LOGIN_PASS, EM_SETPASSWORDCHAR, L'*', 0);
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK)
        {
            LoginData* d = (LoginData*)GetWindowLongPtrW(h, DWLP_USER);
            GetDlgItemTextW(h, IDC_LOGIN_NAME, d->name, MAXNAME);
            GetDlgItemTextW(h, IDC_LOGIN_PASS, d->pass, MAXPASS);
            if (d->name[0] == 0) { SetFocus(GetDlgItem(h, IDC_LOGIN_NAME)); return TRUE; }
            EndDialog(h, IDOK);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) { EndDialog(h, IDCANCEL); return TRUE; }
        break;
    }
    return FALSE;
}

struct ChangeData
{
    Account* acc;
    bool needOld;
    bool hideOld;
};

static INT_PTR CALLBACK ChangeProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {

    case WM_INITDIALOG:
    {
        SetWindowLongPtrW(h, DWLP_USER, lp);
        ChangeData* d = (ChangeData*)lp;

        const int ids[3] = { IDC_CP_OLD, IDC_CP_NEW, IDC_CP_CONF };
        for (int i = 0; i < 3; ++i)
        {
            SendDlgItemMessageW(h, ids[i], EM_LIMITTEXT, MAXPASS - 1, 0);
            SendDlgItemMessageW(h, ids[i], EM_SETPASSWORDCHAR, L'*', 0);
        }

        if (d->hideOld)
        {
            SetWindowTextW(h, L"Создание пароля");

            ShowWindow(GetDlgItem(h, IDC_CP_OLD), SW_HIDE);
            ShowWindow(GetDlgItem(h, IDC_CP_OLD_LBL), SW_HIDE);

            SetFocus(GetDlgItem(h, IDC_CP_NEW));
            return FALSE;
        }

        SetFocus(GetDlgItem(h, IDC_CP_OLD));
        return FALSE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK)
        {
            ChangeData* d = (ChangeData*)GetWindowLongPtrW(h, DWLP_USER);
            wchar_t o[MAXPASS], n1[MAXPASS], n2[MAXPASS];
            GetDlgItemTextW(h, IDC_CP_OLD, o, MAXPASS);
            GetDlgItemTextW(h, IDC_CP_NEW, n1, MAXPASS);
            GetDlgItemTextW(h, IDC_CP_CONF, n2, MAXPASS);

            if (d->needOld && wcscmp(o, d->acc->UserPass) != 0)
            {
                MessageBoxW(h, L"Неверный старый пароль!", L"Ошибка", MB_OK | MB_ICONERROR);
                SetFocus(GetDlgItem(h, IDC_CP_OLD));
                return TRUE;
            }
            if (n1[0] == 0)
            {
                MessageBoxW(h, L"Пароль не может быть пустым!", L"Ошибка", MB_OK | MB_ICONERROR);
                SetFocus(GetDlgItem(h, IDC_CP_NEW));
                return TRUE;
            }
            if (wcscmp(n1, n2) != 0)
            {
                MessageBoxW(h, L"Пароли должны совпадать!", L"Ошибка", MB_OK | MB_ICONERROR);
                SetFocus(GetDlgItem(h, IDC_CP_NEW));
                return TRUE;
            }
            if (d->acc->Restrict && !CheckPassword(n1))
            {
                MessageBoxW(h,
                    L"Пароль не соответствует ограничениям!\n"
                    L"Он должен содержать цифры и знаки препинания ( . , - : ; ! ? ( ) \" ).",
                    L"Ошибка", MB_OK | MB_ICONERROR);
                SetFocus(GetDlgItem(h, IDC_CP_NEW));
                return TRUE;
            }
            wcscpy_s(d->acc->UserPass, MAXPASS, n1);
            d->acc->PassLen = (int)wcslen(n1);
            EndDialog(h, IDOK);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) { EndDialog(h, IDCANCEL); return TRUE; }
        break;
    }
    return FALSE;
}

static bool SetPasswordDialog(
    HWND parent,
    Account& a,
    bool askOld = true,
    bool hideOld = false)
{
    ChangeData d = {
        &a,
        askOld && a.PassLen > 0,
        hideOld
    };

    return DialogBoxParamW(
        g_hInst,
        MAKEINTRESOURCEW(IDD_CHANGEPASS),
        parent,
        ChangeProc,
        (LPARAM)&d
    ) == IDOK;
}

enum LoginResult
{
    LOGIN_OK,
    LOGIN_CANCEL,
    LOGIN_FATAL
};

static LoginResult DoLogin(HWND parent)
{
    int tries = 0;
    for (;;)
    {
        LoginData ld;
        memset(&ld, 0, sizeof(ld));
        if (DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_LOGIN), parent,
                            LoginProc, (LPARAM)&ld) != IDOK)
            return LOGIN_CANCEL;

        std::vector<Account> v;
        LoadAll(v);
        int idx = FindUser(v, ld.name);

        if (idx < 0)
        {
            if (MessageBoxW(parent, L"Вы не зарегистрированы!\nПовторить ввод имени?",
                            L"Ошибка", MB_RETRYCANCEL | MB_ICONERROR) == IDRETRY)
                continue;
            return LOGIN_CANCEL;
        }
        Account a = v[idx];

        if (a.Block)
        {
            MessageBoxW(parent, L"Вы заблокированы!", L"Ошибка", MB_OK | MB_ICONERROR);
            continue;
        }

        if (a.PassLen == 0)
        {

            if (!SetPasswordDialog(parent, a, false, true))
                return LOGIN_CANCEL;

            v[idx] = a;

            if (!SaveAll(v))
            {
                MessageBoxW(parent,
                    L"Не удалось сохранить новый пароль!",
                    L"Ошибка", MB_OK | MB_ICONERROR);
                return LOGIN_FATAL;
            }

            continue;
        }
        else if (wcscmp(a.UserPass, ld.pass) != 0)
        {
            if (++tries >= MAX_TRIES)
            {
                MessageBoxW(parent, L"Пароль введен неверно три раза.\nРабота программы завершается.",
                            L"Ошибка", MB_OK | MB_ICONERROR);
                return LOGIN_FATAL;
            }
            MessageBoxW(parent, L"Неверный пароль! Повторите ввод.", L"Ошибка", MB_OK | MB_ICONERROR);
            continue;
        }

        if (a.PassLen > 0 && a.Restrict && !CheckPassword(a.UserPass))
        {
            MessageBoxW(parent,
                L"Текущий пароль не соответствует ограничениям.\n"
                L"Необходимо задать новый пароль.",
                L"Смена пароля",
                MB_OK | MB_ICONINFORMATION);

            if (!SetPasswordDialog(parent, a, true, false))
            {
                MessageBoxW(parent,
                    L"Вход невозможен, пока пароль не будет изменен.",
                    L"Ошибка",
                    MB_OK | MB_ICONERROR);

                return LOGIN_CANCEL;
            }

            v[idx] = a;

            if (!SaveAll(v))
            {
                MessageBoxW(parent,
                    L"Не удалось сохранить новый пароль!",
                    L"Ошибка",
                    MB_OK | MB_ICONERROR);

                return LOGIN_FATAL;
            }

            continue;
        }

        g_cur = a;
        g_admin = (wcscmp(a.UserName, ADMIN_NAME) == 0);
        g_logged = true;
        return LOGIN_OK;
    }
}

static INT_PTR CALLBACK NewUserProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_INITDIALOG:
        SetWindowLongPtrW(h, DWLP_USER, lp);
        SendDlgItemMessageW(h, IDC_NU_NAME, EM_LIMITTEXT, MAXNAME - 1, 0);
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK)
        {
            wchar_t* out = (wchar_t*)GetWindowLongPtrW(h, DWLP_USER);
            wchar_t name[MAXNAME];
            GetDlgItemTextW(h, IDC_NU_NAME, name, MAXNAME);
            if (name[0] == 0) { SetFocus(GetDlgItem(h, IDC_NU_NAME)); return TRUE; }

            std::vector<Account> v;
            LoadAll(v);
            if (FindUser(v, name) >= 0)
            {
                std::wstring m = std::wstring(L"Пользователь ") + name + L"\nуже зарегистрирован!";
                MessageBoxW(h, m.c_str(), L"Ошибка", MB_OK | MB_ICONERROR);
                SetFocus(GetDlgItem(h, IDC_NU_NAME));
                return TRUE;
            }
            wcscpy_s(out, MAXNAME, name);
            EndDialog(h, IDOK);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) { EndDialog(h, IDCANCEL); return TRUE; }
        break;
    }
    return FALSE;
}

static void SwitchUser(HWND h);

static void AddUser(HWND parent)
{
    wchar_t name[MAXNAME] = L"";

    if (DialogBoxParamW(
        g_hInst,
        MAKEINTRESOURCEW(IDD_NEWUSER),
        parent,
        NewUserProc,
        (LPARAM)name) != IDOK)
        return;

    std::vector<Account> v;
    LoadAll(v);

    if (FindUser(v, name) >= 0)
    {
        std::wstring m =
            std::wstring(L"Пользователь ") + name +
            L"\nуже зарегистрирован!";

        MessageBoxW(parent, m.c_str(),
            L"Ошибка", MB_OK | MB_ICONERROR);
        return;
    }

    Account a;
    memset(&a, 0, sizeof(a));

    wcscpy_s(a.UserName, MAXNAME, name);
    a.PassLen = 0;
    a.Block = false;
    a.Restrict = true;

    v.push_back(a);

    if (!SaveAll(v))
    {
        MessageBoxW(parent,
            L"Не удалось сохранить нового пользователя!",
            L"Ошибка", MB_OK | MB_ICONERROR);
        return;
    }

    MessageBoxW(parent,
        L"Пользователь успешно добавлен.\n"
        L"Пароль будет создан при первом входе.",
        L"Создание пользователя",
        MB_OK | MB_ICONINFORMATION);
}

struct UsersData { std::vector<Account> v; size_t i; };

static void ShowRec(HWND h, UsersData* d)
{
    const Account& a = d->v[d->i];
    SetDlgItemTextW(h, IDC_USR_NAME, a.UserName);
    CheckDlgButton(h, IDC_USR_BLOCK, a.Block ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(h, IDC_USR_RESTR, a.Restrict ? BST_CHECKED : BST_UNCHECKED);

    EnableWindow(GetDlgItem(h, IDC_USR_BLOCK), wcscmp(a.UserName, ADMIN_NAME) != 0);
    EnableWindow(GetDlgItem(h, IDC_USR_PREV), d->i > 0);
    EnableWindow(GetDlgItem(h, IDC_USR_NEXT), d->i + 1 < d->v.size());
    wchar_t buf[32];
    swprintf_s(buf, L"%u из %u", (unsigned)(d->i + 1), (unsigned)d->v.size());
    SetDlgItemTextW(h, IDC_USR_COUNT, buf);
}

static INT_PTR CALLBACK UsersProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_INITDIALOG:
        SetWindowLongPtrW(h, DWLP_USER, lp);
        ShowRec(h, (UsersData*)lp);
        return TRUE;
    case WM_COMMAND:
    {
        UsersData* d = (UsersData*)GetWindowLongPtrW(h, DWLP_USER);
        switch (LOWORD(wp))
        {
        case IDC_USR_NEXT:
            if (d->i + 1 < d->v.size()) { ++d->i; ShowRec(h, d); }
            return TRUE;
        case IDC_USR_PREV:
            if (d->i > 0) { --d->i; ShowRec(h, d); }
            return TRUE;
        case IDC_USR_SAVE:
            d->v[d->i].Block    = IsDlgButtonChecked(h, IDC_USR_BLOCK) == BST_CHECKED;
            d->v[d->i].Restrict = IsDlgButtonChecked(h, IDC_USR_RESTR) == BST_CHECKED;
            SaveAll(d->v);
            return TRUE;
        case IDOK:
        case IDCANCEL:
            EndDialog(h, LOWORD(wp));
            return TRUE;
        }
        break;
    }
    }
    return FALSE;
}

static void ShowUsers(HWND parent)
{
    UsersData d;
    LoadAll(d.v);
    d.i = 0;
    if (d.v.empty()) return;
    DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_USERS), parent, UsersProc, (LPARAM)&d);
}

static void ChangeOwnPassword(HWND parent)
{
    std::vector<Account> v;
    LoadAll(v);

    int idx = FindUser(v, g_cur.UserName);
    if (idx < 0) return;

    Account a = v[idx];

    if (!SetPasswordDialog(parent, a))
        return;

    v[idx] = a;

    if (!SaveAll(v))
    {
        MessageBoxW(parent,
            L"Не удалось сохранить новый пароль!",
            L"Ошибка", MB_OK | MB_ICONERROR);
        return;
    }

    g_cur = a;
}

static INT_PTR CALLBACK AboutProc(HWND h, UINT msg, WPARAM wp, LPARAM)
{
    switch (msg)
    {
    case WM_INITDIALOG:
        SetDlgItemTextW(h, IDC_ABOUT_TEXT,
            L"Автор: Горбачев Святослав Антонович, группа ИДБ-23-01\r\n"
            L"Лабораторная работа №1, вариант 5: наличие цифр и знаков препинания в пароле\r\n"
            L"Лабораторная работа №3, вариант 5: блочный шифр, обратная связь по шифротексту, добавление случайного значения, MD2");
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK || LOWORD(wp) == IDCANCEL) { EndDialog(h, 0); return TRUE; }
        break;
    }
    return FALSE;
}

struct PhData { wchar_t pass[MAXPH]; bool first; };

static INT_PTR CALLBACK PassphraseProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_INITDIALOG:
    {
        SetWindowLongPtrW(h, DWLP_USER, lp);
        PhData* d = (PhData*)lp;
        const int ids[2] = { IDC_PH_PASS, IDC_PH_CONF };
        for (int i = 0; i < 2; ++i)
        {
            SendDlgItemMessageW(h, ids[i], EM_LIMITTEXT, MAXPH - 1, 0);
            SendDlgItemMessageW(h, ids[i], EM_SETPASSWORDCHAR, L'*', 0);
        }
        if (d->first)
            SetDlgItemTextW(h, IDC_PH_TEXT,
                L"Первый запуск. Задайте парольную фразу для шифрования файла учетных записей:");
        else
        {
            ShowWindow(GetDlgItem(h, IDC_PH_CONF), SW_HIDE);
            ShowWindow(GetDlgItem(h, IDC_PH_CONF_LBL), SW_HIDE);
        }
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK)
        {
            PhData* d = (PhData*)GetWindowLongPtrW(h, DWLP_USER);
            wchar_t p1[MAXPH], p2[MAXPH];
            GetDlgItemTextW(h, IDC_PH_PASS, p1, MAXPH);
            GetDlgItemTextW(h, IDC_PH_CONF, p2, MAXPH);
            if (p1[0] == 0) { SetFocus(GetDlgItem(h, IDC_PH_PASS)); return TRUE; }
            if (d->first && wcscmp(p1, p2) != 0)
            {
                MessageBoxW(h, L"Парольные фразы должны совпадать!", L"Ошибка", MB_OK | MB_ICONERROR);
                SetFocus(GetDlgItem(h, IDC_PH_PASS));
                SecureZeroMemory(p1, sizeof(p1)); SecureZeroMemory(p2, sizeof(p2));
                return TRUE;
            }
            wcscpy_s(d->pass, MAXPH, p1);
            SecureZeroMemory(p1, sizeof(p1)); SecureZeroMemory(p2, sizeof(p2));
            EndDialog(h, IDOK);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) { EndDialog(h, IDCANCEL); return TRUE; }
        break;
    }
    return FALSE;
}

static bool InitDatabase(HWND parent)
{
    bool exists = GetFileAttributesW(ENCFILE) != INVALID_FILE_ATTRIBUTES;
    PhData d;
    memset(&d, 0, sizeof(d));
    d.first = !exists;
    if (DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_PASSPHRASE), parent,
                        PassphraseProc, (LPARAM)&d) != IDOK)
    {
        MessageBoxW(parent, L"Парольная фраза не введена.\nРабота программы завершается.",
                    L"Ошибка", MB_OK | MB_ICONERROR);
        return false;
    }
    wcscpy_s(g_pass, MAXPH, d.pass);
    SecureZeroMemory(&d, sizeof(d));

    if (!exists)
    {
        Account a;
        memset(&a, 0, sizeof(a));
        wcscpy_s(a.UserName, MAXNAME, ADMIN_NAME);
        a.PassLen = 0;
        a.Block = false;
        a.Restrict = true;
        g_db.assign(1, a);
        if (!EncryptDb(g_db, g_pass))
        {
            MessageBoxW(parent, L"Не удалось создать зашифрованный файл учетных записей.\n"
                                L"Возможно, провайдер не поддерживает выбранные алгоритмы.",
                        L"Ошибка", MB_OK | MB_ICONERROR);
            return false;
        }
    }
    else if (!DecryptDb(g_db, g_pass))
    {
        MessageBoxW(parent, L"Неверная парольная фраза или поврежден файл учетных записей.\n"
                            L"Работа программы завершается.",
                    L"Ошибка", MB_OK | MB_ICONERROR);
        return false;
    }
    g_loaded = true;
    return true;
}

static void UpdateMenu(HWND h)
{
    HMENU m = GetMenu(h);
    EnableMenuItem(m, IDM_SWITCH, MF_BYCOMMAND | (g_logged ? MF_ENABLED : MF_GRAYED));
    EnableMenuItem(m, IDM_CHANGE, MF_BYCOMMAND | (g_logged ? MF_ENABLED : MF_GRAYED));
    EnableMenuItem(m, IDM_ALL,    MF_BYCOMMAND | (g_logged && g_admin ? MF_ENABLED : MF_GRAYED));
    EnableMenuItem(m, IDM_NEW,    MF_BYCOMMAND | (g_logged && g_admin ? MF_ENABLED : MF_GRAYED));
    DrawMenuBar(h);
    std::wstring t = L"Разграничение полномочий пользователей";
    if (g_logged) t += std::wstring(L" - ") + g_cur.UserName;
    SetWindowTextW(h, t.c_str());
    InvalidateRect(h, NULL, TRUE);
}

static void SwitchUser(HWND h)
{
    ShowWindow(h, SW_HIDE);
    LoginResult r = DoLogin(NULL);
    if (r == LOGIN_OK)
    {
        UpdateMenu(h);
        ShowWindow(h, SW_SHOW);
    }
    else if (r == LOGIN_CANCEL)
        ShowWindow(h, SW_SHOW);
    else
        DestroyWindow(h);
}

static LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_COMMAND:
        switch (LOWORD(wp))
        {
        case IDM_SWITCH: if (g_logged) SwitchUser(h); return 0;
        case IDM_EXIT:   DestroyWindow(h); return 0;
        case IDM_CHANGE: if (g_logged) ChangeOwnPassword(h); return 0;
        case IDM_ALL:    if (g_logged && g_admin) ShowUsers(h); return 0;
        case IDM_NEW:    if (g_logged && g_admin) AddUser(h); return 0;
        case IDM_ABOUT:
            DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_ABOUT), h, AboutProc, 0);
            return 0;
        }
        break;
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        RECT r;
        GetClientRect(h, &r);
        SetBkMode(dc, TRANSPARENT);
        std::wstring s;
        if (g_logged)
        {
            s = std::wstring(L"Пользователь: ") + g_cur.UserName +
                (g_admin ? L"\r\nРежим: администратор" : L"\r\nРежим: обычный пользователь");
        }
        else s = L"Вход не выполнен";
        DrawTextW(dc, s.c_str(), -1, &r, DT_CENTER | DT_VCENTER | DT_WORDBREAK);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_DESTROY:

        if (g_loaded) EncryptDb(g_db, g_pass);
        SecureZeroMemory(g_pass, sizeof(g_pass));
        if (!g_db.empty()) SecureZeroMemory(&g_db[0], g_db.size() * sizeof(Account));
        g_db.clear();
        SecureZeroMemory(&g_cur, sizeof(g_cur));
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nShow)
{
    g_hInst = hInst;

    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszMenuName = MAKEINTRESOURCEW(IDR_MAINMENU);
    wc.lpszClassName = L"Lab1Wnd";
    RegisterClassExW(&wc);

    HWND h = CreateWindowExW(0, L"Lab1Wnd", L"Разграничение полномочий пользователей",
                             WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 520, 300,
                             NULL, NULL, hInst, NULL);

    if (InitDatabase(NULL) && DoLogin(NULL) == LOGIN_OK)
    {
        UpdateMenu(h);
        ShowWindow(h, nShow);
        UpdateWindow(h);
    }
    else DestroyWindow(h);

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0)
    {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    return (int)m.wParam;
}
