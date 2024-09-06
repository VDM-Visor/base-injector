import ctypes
import ctypes.wintypes
import win32api
import win32gui
import win32process
import win32con

# Outdated
class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [("e_lfanew", ctypes.c_uint32)]

class IMAGE_NT_HEADERS(ctypes.Structure):
    class OPTIONAL_HEADER(ctypes.Structure):
        _fields_ = [("SizeOfCode", ctypes.c_uint32)]
    _fields_ = [("OptionalHeader", OPTIONAL_HEADER)]

class PHYSICAL_ADDRESS(ctypes.Structure):
    _fields_ = [("QuadPart", ctypes.c_uint64)]

# Load libraries
def load_library(name):
    return ctypes.windll.kernel32.LoadLibraryW(name)

def get_ntk_export(name, export_name):
    kernel32 = ctypes.windll.kernel32
    h_kernel = kernel32.LoadLibraryW(name)
    if not h_kernel:
        raise RuntimeError(f"Failed to load the {name} library")
    export_address = kernel32.GetProcAddress(h_kernel, export_name.encode('utf-8'))
    if not export_address:
        raise RuntimeError(f"Export {export_name} was not found or is broken")
    return export_address

def get_physical_address(vdm, virtual_address):
    mm_get_physical_address = get_ntk_export("ntoskrnl.exe", "MmGetPhysicalAddress")
    get_physical_address_func = ctypes.CFUNCTYPE(PHYSICAL_ADDRESS, ctypes.c_uint64)(mm_get_physical_address)
    physical_address = get_physical_address_func(virtual_address)
    return physical_address.QuadPart

def get_nt_headers(image_base):
    dos_header = ctypes.cast(image_base, ctypes.POINTER(IMAGE_DOS_HEADER))
    nt_headers_address = image_base + dos_header.contents.e_lfanew
    return ctypes.cast(nt_headers_address, ctypes.POINTER(IMAGE_NT_HEADERS))

def write_phys(address, data, size):
    # Phys-Mem is insanely hard in python, you is will need to write your own
    # print(f"[+] Writing {size} bytes to physical address {hex(address)}")

def set_windows_hook(hook_proc, module_handle, thread_id):
    hook_id = ctypes.windll.user32.SetWindowsHookExW(win32con.WH_KEYBOARD, hook_proc, module_handle, thread_id)
    if not hook_id:
        raise RuntimeError("Failed to set hook")
    return hook_id

def main():
    driver_handle = load_library("vdm.dll")
    if not driver_handle:
        print("[!] Driver did not load")
        return

    module_holder = load_library("holder.dll")
    module_inject = load_library("module.dll")

    if not module_holder or not module_inject:
        print("[!] Failed to load one or more modules")
        return

    modules = (module_holder, module_inject)

    vdm = ctypes.windll.vdm # You will need your own VDM 

    def write_region(virtual_address, data_address, size):
        physical_address = get_physical_address(vdm, virtual_address)
        write_phys(physical_address, data_address, size)

    nt_headers = get_nt_headers(modules[1])
    size_of_code = nt_headers.contents.OptionalHeader.SizeOfCode

    print(f"[+] Size of code: {size_of_code:X}")

    
    # ctypes.windll.kernel32.VirtualLock(...)

    remainder = size_of_code % 0x1000

    if (size_of_code - remainder) >= 0x1000:
        for page in range(0x1000, size_of_code - remainder, 0x1000):
            print(f"[+] Writing region with size 0x1000 at holder+{page + 0x1000:X}")
            write_region(modules[0] + page + 0x1000, modules[1] + page, 0x1000)

    if remainder:
        print(f"[+] Writing region with size {remainder:X} at holder+{(size_of_code - remainder) + 0x2000:X}")
        write_region(modules[0] + (size_of_code - remainder) + 0x2000, modules[1] + (size_of_code - remainder) + 0x1000, remainder)

    print("[+] Once game open press 'Enter'")
    print("[+] Start hit keys on keyboard for injection")

    input()

    window_title = "UnrealWindow"
    hwnd = win32gui.FindWindow(None, window_title)
    if hwnd == 0:
        print(f"[!] Window '{window_title}' not found")
        return

    _, process_id = win32process.GetWindowThreadProcessId(hwnd)
    if not process_id:
        print("[!] Process ID not found...")
        return

    hook_proc = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int)(modules[0] + 0x2000)
    hook_id = set_windows_hook(hook_proc, modules[0], win32process.GetWindowThreadProcessId(hwnd)[1])

    print("[+] Finished")
    input()

if __name__ == "__main__":
    main()
