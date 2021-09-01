// FileIntegrity.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iomanip>
#include <iostream>
#include <string>

#include <Windows.h>
#include <aclapi.h>
#include <fileapi.h>
#include <sddl.h>

#ifndef SE_DACL_UNTRUSTED
#define SE_DACL_UNTRUSTED                (0x0040)
#endif
#ifndef SE_SERVER_SECURITY
#define SE_SERVER_SECURITY               (0x0080)
#endif

std::wstring AsString(SECURITY_DESCRIPTOR_CONTROL sc) {
  std::wstring result;
  if (sc & SE_OWNER_DEFAULTED) {if (!result.empty()) result.append(L" "); result.append(L"SE_OWNER_DEFAULTED"); sc &= ~SE_OWNER_DEFAULTED; }
  if (sc & SE_GROUP_DEFAULTED) {if (!result.empty()) result.append(L" "); result.append(L"SE_GROUP_DEFAULTED"); sc &= ~SE_GROUP_DEFAULTED; }
  if (sc & SE_DACL_PRESENT) {if (!result.empty()) result.append(L" "); result.append(L"SE_DACL_PRESENT"); sc &= ~SE_DACL_PRESENT; }
  if (sc & SE_DACL_DEFAULTED) {if (!result.empty()) result.append(L" "); result.append(L"SE_DACL_DEFAULTED"); sc &= ~SE_DACL_DEFAULTED; }
  if (sc & SE_SACL_PRESENT) {if (!result.empty()) result.append(L" "); result.append(L"SE_SACL_PRESENT"); sc &= ~SE_SACL_PRESENT; }
  if (sc & SE_SACL_DEFAULTED) {if (!result.empty()) result.append(L" "); result.append(L"SE_SACL_DEFAULTED"); sc &= ~SE_SACL_DEFAULTED; }
  if (sc & SE_DACL_UNTRUSTED) {if (!result.empty()) result.append(L" "); result.append(L"SE_DACL_UNTRUSTED"); sc &= ~SE_DACL_UNTRUSTED; }
  if (sc & SE_SERVER_SECURITY) {if (!result.empty()) result.append(L" "); result.append(L"SE_SERVER_SECURITY"); sc &= ~SE_SERVER_SECURITY; }
  if (sc & SE_DACL_AUTO_INHERIT_REQ) {if (!result.empty()) result.append(L" "); result.append(L"SE_DACL_AUTO_INHERIT_REQ"); sc &= ~SE_DACL_AUTO_INHERIT_REQ; }
  if (sc & SE_SACL_AUTO_INHERIT_REQ) {if (!result.empty()) result.append(L" "); result.append(L"SE_SACL_AUTO_INHERIT_REQ"); sc &= ~SE_SACL_AUTO_INHERIT_REQ; }
  if (sc & SE_DACL_AUTO_INHERITED) {if (!result.empty()) result.append(L" "); result.append(L"SE_DACL_AUTO_INHERITED"); sc &= ~SE_DACL_AUTO_INHERITED; }
  if (sc & SE_SACL_AUTO_INHERITED) {if (!result.empty()) result.append(L" "); result.append(L"SE_SACL_AUTO_INHERITED"); sc &= ~SE_SACL_AUTO_INHERITED; }
  if (sc & SE_DACL_PROTECTED ) {if (!result.empty()) result.append(L" "); result.append(L"SE_DACL_PROTECTED "); sc &= ~SE_DACL_PROTECTED ; }
  if (sc & SE_SACL_PROTECTED) {if (!result.empty()) result.append(L" "); result.append(L"SE_SACL_PROTECTED"); sc &= ~SE_SACL_PROTECTED; }
  if (sc & SE_RM_CONTROL_VALID) {if (!result.empty()) result.append(L" "); result.append(L"SE_RM_CONTROL_VALID"); sc &= ~SE_RM_CONTROL_VALID; }
  if (sc & SE_SELF_RELATIVE) {if (!result.empty()) result.append(L" "); result.append(L"SE_SELF_RELATIVE"); sc &= ~SE_SELF_RELATIVE; }
  return result;
}

std::ostream& operator<<(SECURITY_DESCRIPTOR_CONTROL sc, std::ostream& os) {
  return os << AsString(sc).c_str();
}

class HandleCloser {
 public:
  HandleCloser(HANDLE h) : h_(h) {}
  HANDLE h() { return h_; };
  operator HANDLE() { return h_; }
  operator bool() { return h_ != INVALID_HANDLE_VALUE; }
  ~HandleCloser() {
    if (h() != INVALID_HANDLE_VALUE) {
      CloseHandle(h_);
      h_ = INVALID_HANDLE_VALUE;
    }
  }

 private:
  HANDLE h_{INVALID_HANDLE_VALUE};
};

template <typename T>
class Closer {
 public:
  Closer() = default;
  explicit Closer(uint32_t size) : storage_((T)LocalAlloc(LPTR, size)){}
  ~Closer() {
    if (storage_) {
      LocalFree(storage_);
      storage_ = nullptr;
    }
  }
  operator T() { return storage_; }
  operator bool() { return storage_ != nullptr; }
  T get() { return storage_; }
  T* get_address() { return &storage_; }
 private:
  T storage_{nullptr};
};

int wmain(_In_range_(>, 0) int argc, _In_reads_(argc) wchar_t* argv[]) {
  constexpr std::ios_base::fmtflags kFlags =
      std::ios_base::hex | std::ios_base::showbase | std::ios_base::boolalpha;
  DWORD last_error = NOERROR;
  int failure_count = 0;
  for (int i = 1; i < argc; i++) {
    std::wstring file_name(argv[i]);
    HRESULT hr = S_OK;
    if (i > 1) {
      std::wcout << std::endl;
    }
    std::wcout << "Opening file \"" << std::wstring(file_name).c_str() << "\"" << std::endl;
    HandleCloser h(CreateFile2(file_name.c_str(), READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    OPEN_EXISTING, nullptr));
    if (h == INVALID_HANDLE_VALUE) {
      last_error = GetLastError();
      std::wcout << "Cannot open \"" << file_name << "\"; error = " << std::dec
                 << last_error << " (" << std::hex << std::showbase
                 << last_error << ")" << std::resetiosflags(kFlags)
                 << std::endl;
      ++failure_count;
      continue;
    }
    std::wcout << L"CreateFile2(\"" << argv[i] << "\") = " << std::hex
               << std::showbase << h.h() << std::resetiosflags(kFlags) << std::endl;

    DWORD sd_size = 0;
    PSECURITY_DESCRIPTOR tempsd = nullptr;
    BOOL get_security_result = GetKernelObjectSecurity(
        h, LABEL_SECURITY_INFORMATION, tempsd, sd_size, &sd_size);
    if (!get_security_result) {
      last_error = GetLastError();
      if (last_error != ERROR_INSUFFICIENT_BUFFER) {
        std::wcout << "GetKernelObjectSecurity for \"" << file_name.c_str()
                   << "\"; error = " << std::dec << last_error << " ("
                   << std::hex << std::showbase << last_error << ")"
                   << std::resetiosflags(kFlags) << std::endl;
        ++failure_count;
        continue;
      }
    }

    Closer<PSECURITY_DESCRIPTOR> psd(sd_size);
    get_security_result = GetKernelObjectSecurity(h, LABEL_SECURITY_INFORMATION,
                                                  psd.get(), sd_size, &sd_size);
    if (!get_security_result || !psd) {
      last_error = GetLastError();
      if (!psd && !last_error) {
        last_error = ERROR_OUTOFMEMORY;
      }
      std::wcout << "GetKernelObjectSecurity for \"" << file_name.c_str()
                 << "\"; error = " << std::dec << last_error << " (" << std::hex
                 << std::showbase << last_error << ")"
                 << std::resetiosflags(kFlags) << std::endl;
      ++failure_count;
      continue;
    }
    Closer<LPWSTR> text(0);
    ULONG text_length = 0;
    ULONG sd_length = GetSecurityDescriptorLength(psd.get());
    DWORD revision = 0xFFFFFFFF;
    SECURITY_DESCRIPTOR_CONTROL sd_control = 0;
    GetSecurityDescriptorControl(psd.get(), &sd_control, &revision);
    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd.get(), SDDL_REVISION_1, LABEL_SECURITY_INFORMATION, text.get_address(),
            &text_length)) {
      std::wcout << "Security descriptor for file (" << text_length
                 << ") = " << std::hex << std::showbase << psd.get()
                 << std::resetiosflags(kFlags) << " (" << sd_length
                 << " bytes); control = " << std::hex << sd_control << " ("
                 << AsString(sd_control)
                 << "); value = \"" << (LPWSTR)text << "\""
                 << std::resetiosflags(kFlags) << std::endl;
    }

    BOOL sacl_present = FALSE;
    BOOL sacl_defaulted = TRUE;
    PACL sacl = nullptr;
    get_security_result =
        GetSecurityDescriptorSacl(psd, &sacl_present, &sacl, &sacl_defaulted);
    if (!get_security_result) {
      last_error = GetLastError();
      std::wcout << "GetSecurityDescriptorSacl for \"" << file_name.c_str()
                 << "\"; error = " << std::dec << last_error << " (" << std::hex
                 << std::showbase << last_error << ")"
                 << std::resetiosflags(kFlags) << std::endl;
      ++failure_count;
      continue;
    }
    if (!sacl_present || sacl_defaulted) {
      std::wcout << "No SACL present to analyze." << std::endl;
      continue;
    }
    std::wcout << "Got SACL for SECURITY_DESCRIPTOR; sacl_present = "
               << std::boolalpha << (bool)sacl_present
               << "; sacl_defaulted = " << (bool)sacl_defaulted
               << "; sacl->AceCount = " << sacl->AceCount
               << std::resetiosflags(kFlags) << std::endl;
    PACCESS_ALLOWED_ACE ace = nullptr;
    if (sacl->AceCount > 0) {
      get_security_result = GetAce(sacl, 0, reinterpret_cast<void**>(&ace));
      if (!get_security_result) {
        std::wcout << "GetAce: error = " << std::dec << last_error << " ("
                   << std::hex << std::showbase << last_error << ")"
                   << std::resetiosflags(kFlags) << std::endl;
        continue;
      } else {
        std::wcout << "GetAce: retrieved the ACE at position 0." << std::endl;
      }
    } else {
      std::wcout
          << "No ACE is present in the SACL to determine integrity level."
          << std::endl;
      continue;
    }

    PSID sid = &ace->SidStart;
    auto sid_length = GetLengthSid(sid);
    Closer<PSID> integrity_sid(sid_length);
    get_security_result = CopySid(sid_length, integrity_sid, sid);
    if (!get_security_result) {
      last_error = GetLastError();
      std::wcout << "CopySid for " << sid_length
                 << " bytes; error = " << std::dec << last_error << " ("
                 << std::hex << std::showbase << last_error << ")"
                 << std::resetiosflags(kFlags) << std::endl;
      ++failure_count;
      continue;
    }

    if (!IsValidSid(integrity_sid)) {
      last_error = GetLastError();
      std::wcout << "IsValidSid for integrity_sid; error = " << std::dec
                 << last_error << " (" << std::hex << std::showbase
                 << last_error << ")" << std::resetiosflags(kFlags)
                 << std::endl;
      ++failure_count;
      continue;
    }

    UCHAR sub_authority_count = *GetSidSubAuthorityCount(integrity_sid);
    std::wcout << "integity SID sub_authority_count = "
               << static_cast<int>(sub_authority_count) << std::endl;
    if (sub_authority_count > 0) {
      DWORD* integrity_rid_pointer =
          GetSidSubAuthority(integrity_sid, sub_authority_count - 1);
      std::wcout << "integrity_rid = " << std::dec << *integrity_rid_pointer
                 << std::hex << std::showbase << " (" << *integrity_rid_pointer
                 << ")" << std::resetiosflags(kFlags) << std::endl;
    } else {
      std::wcout << "No RID to see -- sub_authority_count is zero."
                 << std::endl;
    }
  }
  return failure_count;
}

