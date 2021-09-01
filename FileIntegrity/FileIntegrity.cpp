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

std::wstring RidAsString(DWORD rid) {
  if (rid == SECURITY_MANDATORY_UNTRUSTED_RID) return L"SECURITY_MANDATORY_UNTRUSTED_RID";
  if (rid == SECURITY_MANDATORY_LOW_RID) return L"SECURITY_MANDATORY_LOW_RID";
  if (rid == SECURITY_MANDATORY_MEDIUM_RID) return L"SECURITY_MANDATORY_MEDIUM_RID";
  if (rid == SECURITY_MANDATORY_MEDIUM_PLUS_RID) return L"SECURITY_MANDATORY_MEDIUM_PLUS_RID";
  if (rid == SECURITY_MANDATORY_HIGH_RID) return L"SECURITY_MANDATORY_HIGH_RID";
  if (rid == SECURITY_MANDATORY_SYSTEM_RID) return L"SECURITY_MANDATORY_SYSTEM_RID";
  if (rid == SECURITY_MANDATORY_PROTECTED_PROCESS_RID) return L"SECURITY_MANDATORY_PROTECTED_PROCESS_RID";
  return L"(UNKNOWN RID)";
}

std::wstring AceTypeAsString(BYTE ace_type) {
  if (ace_type == ACCESS_ALLOWED_ACE_TYPE)
    return L"ACCESS_ALLOWED_ACE_TYPE";
  if (ace_type == ACCESS_DENIED_ACE_TYPE)
    return L"ACCESS_DENIED_ACE_TYPE";
  if (ace_type == SYSTEM_AUDIT_ACE_TYPE)
    return L"SYSTEM_AUDIT_ACE_TYPE";
  if (ace_type == SYSTEM_ALARM_ACE_TYPE)
    return L"SYSTEM_ALARM_ACE_TYPE";
  if (ace_type == ACCESS_ALLOWED_COMPOUND_ACE_TYPE)
    return L"ACCESS_ALLOWED_COMPOUND_ACE_TYPE";
  if (ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE)
    return L"ACCESS_ALLOWED_OBJECT_ACE_TYPE";
  if (ace_type == ACCESS_DENIED_OBJECT_ACE_TYPE)
    return L"ACCESS_DENIED_OBJECT_ACE_TYPE";
  if (ace_type == SYSTEM_AUDIT_OBJECT_ACE_TYPE)
    return L"SYSTEM_AUDIT_OBJECT_ACE_TYPE";
  if (ace_type == SYSTEM_ALARM_OBJECT_ACE_TYPE)
    return L"SYSTEM_ALARM_OBJECT_ACE_TYPE";
  if (ace_type == ACCESS_ALLOWED_CALLBACK_ACE_TYPE)
    return L"ACCESS_ALLOWED_CALLBACK_ACE_TYPE";
  if (ace_type == ACCESS_DENIED_CALLBACK_ACE_TYPE)
    return L"ACCESS_DENIED_CALLBACK_ACE_TYPE";
  if (ace_type == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE)
    return L"ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE";
  if (ace_type == ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE)
    return L"ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE";
  if (ace_type == SYSTEM_AUDIT_CALLBACK_ACE_TYPE)
    return L"SYSTEM_AUDIT_CALLBACK_ACE_TYPE";
  if (ace_type == SYSTEM_ALARM_CALLBACK_ACE_TYPE)
    return L"SYSTEM_ALARM_CALLBACK_ACE_TYPE";
  if (ace_type == SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE)
    return L"SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE";
  if (ace_type == SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE)
    return L"SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE";
  if (ace_type == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
    return L"SYSTEM_MANDATORY_LABEL_ACE_TYPE";
  return L"(UNKNOWN AceType)";
}

std::wstring AceFlagsAsString(BYTE f) {
  std::wstring result;
  if (f & OBJECT_INHERIT_ACE) {
    if (!result.empty())
      result.append(L" ");
    result.append(L"OBJECT_INHERIT_ACE");
    f &= ~OBJECT_INHERIT_ACE;
  }
  if (f & CONTAINER_INHERIT_ACE) {
    if (!result.empty())
      result.append(L" ");
    result.append(L"CONTAINER_INHERIT_ACE");
    f &= ~CONTAINER_INHERIT_ACE;
  }
  if (f & NO_PROPAGATE_INHERIT_ACE) {
    if (!result.empty())
      result.append(L" ");
    result.append(L"NO_PROPAGATE_INHERIT_ACE");
    f &= ~NO_PROPAGATE_INHERIT_ACE;
  }
  if (f & INHERIT_ONLY_ACE) {
    if (!result.empty())
      result.append(L" ");
    result.append(L"INHERIT_ONLY_ACE");
    f &= ~INHERIT_ONLY_ACE;
  }
  if (f & INHERITED_ACE) {
    if (!result.empty())
      result.append(L" ");
    result.append(L"INHERITED_ACE");
    f &= ~INHERITED_ACE;
  }
  if (f & SUCCESSFUL_ACCESS_ACE_FLAG) {
    if (!result.empty())
      result.append(L" ");
    result.append(L"SUCCESSFUL_ACCESS_ACE_FLAG");
    f &= ~SUCCESSFUL_ACCESS_ACE_FLAG;
  }
  if (f & FAILED_ACCESS_ACE_FLAG) {
    if (!result.empty())
      result.append(L" ");
    result.append(L"FAILED_ACCESS_ACE_FLAG");
    f &= ~FAILED_ACCESS_ACE_FLAG;
  }
  if (f) {
    if (!result.empty())
      result.append(L" ");
    result.append(std::to_wstring(f));
  }  return result;
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
    PACCESS_ALLOWED_ACE aa_ace = nullptr;
    if (sacl->AceCount > 0) {
      get_security_result = GetAce(sacl, 0, reinterpret_cast<void**>(&aa_ace));
      if (!get_security_result) {
        std::wcout << "GetAce: error = " << std::dec << last_error << " ("
                   << std::hex << std::showbase << last_error << ")"
                   << std::resetiosflags(kFlags) << std::endl;
        continue;
      } else {
        std::wcout << "GetAce: retrieved the ACE at position 0." << std::endl;
        std::wcout << "ACE_HEADER:" << std::endl;
        std::wcout << " .AceType = " << std::showbase << std::hex
                   << aa_ace->Header.AceType << " (" << std::resetiosflags(kFlags)
                   << AceTypeAsString(aa_ace->Header.AceType) << ")"
                   << std::endl;
        std::wcout << " .AceFlags = " << std::showbase << std::hex
                   << aa_ace->Header.AceFlags << std::resetiosflags(kFlags)
                   << " (" << AceFlagsAsString(aa_ace->Header.AceFlags)
                   << ")" << std::endl;
        std::wcout << " .AceSize = " << aa_ace->Header.AceSize << std::endl;
      }
    } else {
      std::wcout
          << "No ACE is present in the SACL to determine integrity level."
          << std::endl;
      continue;
    }

    if (aa_ace->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
      PSID sid = &aa_ace->SidStart;
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
      } else {
        std::wcout << "CopySid successful: copied " << sid_length << " bytes."
                   << std::endl;
      }

      if (!IsValidSid(integrity_sid)) {
        last_error = GetLastError();
        std::wcout << "IsValidSid for integrity_sid; error = " << std::dec
                   << last_error << " (" << std::hex << std::showbase
                   << last_error << ")" << std::resetiosflags(kFlags)
                   << std::endl;
        ++failure_count;
        continue;
      } else {
        std::wcout << "The integrity SID is valid." << std::endl;
      }

      UCHAR sub_authority_count = *GetSidSubAuthorityCount(integrity_sid);
      std::wcout << "integity SID sub_authority_count = "
                 << static_cast<int>(sub_authority_count) << std::endl;
      if (sub_authority_count > 0) {
        DWORD* integrity_rid_pointer =
            GetSidSubAuthority(integrity_sid, sub_authority_count - 1);
        std::wcout << "integrity_rid = " << std::dec << *integrity_rid_pointer
                   << std::hex << std::showbase << " ("
                   << *integrity_rid_pointer << " \"" << RidAsString(*integrity_rid_pointer) << "\")"
                   << std::resetiosflags(kFlags) << std::endl;
      } else {
        std::wcout << "No RID to see -- sub_authority_count is zero."
                   << std::endl;
      }
    } else {
      std::wcout << "There is not a SYSTEM_MANDATORY_LABEL_ACE_TYPE ACE to "
                    "show; default = MEDIUM."
                 << std::endl;
    }
  }
  return failure_count;
}

