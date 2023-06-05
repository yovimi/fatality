#include "fatality.h"
#include "font.h"
#include <format>

LONG WINAPI ExceptionHandler(
    _EXCEPTION_POINTERS* ExceptionInfo
)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_INVALID_DISPOSITION)
        return EXCEPTION_CONTINUE_SEARCH;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode >= STATUS_GUARD_PAGE_VIOLATION)
    {
        std::string exception;

        MEMORY_BASIC_INFORMATION mem;

        char file[MAX_PATH];
        if (VirtualQuery(ExceptionInfo->ExceptionRecord->ExceptionAddress, &mem, sizeof(mem)))
        {
            GetModuleFileNameA((HMODULE)mem.AllocationBase, file, MAX_PATH);
            exception += std::format("image: {}\nimage base: 0x{:X}\n", file, (uint64_t)mem.AllocationBase);
        }

        if ((uint64_t)ExceptionInfo->ExceptionRecord->ExceptionCode == 0xE24C4A02)
        {
            MessageBoxA(0, (sk("----------------\nThis lua is not supported =(\n----------------")), (sk("Local Error")), 0);
        }

        if ((uint64_t)ExceptionInfo->ExceptionRecord->ExceptionAddress == ((uint64_t)mem.AllocationBase + 0x211EA1))
        {
            ExceptionInfo->ContextRecord->Eax = (DWORD)0x420F9AE4;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if ((uint64_t)ExceptionInfo->ExceptionRecord->ExceptionAddress == ((uint64_t)mem.AllocationBase + 0x211E9D))
        {
            ExceptionInfo->ContextRecord->Edi = (DWORD)events_listener_alloc;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        else
        {
            exception += std::format("EAX: 0x{:X}\nEBX: 0x{:X}\nECX: 0x{:X}\nEDX: 0x{:X}\nESP: 0x{:X}\nEBP: 0x{:X}\nESI: 0x{:X}\nEDI: 0x{:X}\nException code: 0x{:X}\nException address: 0x{:X}",
                ExceptionInfo->ContextRecord->Eax, ExceptionInfo->ContextRecord->Ebx, ExceptionInfo->ContextRecord->Ecx, ExceptionInfo->ContextRecord->Edx, ExceptionInfo->ContextRecord->Esp, ExceptionInfo->ContextRecord->Ebp, ExceptionInfo->ContextRecord->Esi, ExceptionInfo->ContextRecord->Edi, ExceptionInfo->ExceptionRecord->ExceptionCode, (uint64_t)ExceptionInfo->ExceptionRecord->ExceptionAddress);

            if (ExceptionInfo->ExceptionRecord->ExceptionCode == 0xE06D7363)
                return EXCEPTION_CONTINUE_SEARCH;
            MessageBoxA(0, exception.c_str(), (sk("dont luck (((")), 0);
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }
    else
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

void* original_unsafe_script = nullptr;

void __declspec(safebuffers)unsafe_script_hook()
{
    const char* msg = "Failed load script!";
    uintptr_t messageboxaddr = reinterpret_cast<uintptr_t>(MessageBoxA);
    _asm
    {
        push 0x30
        push msg
        push dword ptr ds : [ebp + 0x10]
        push 0
        call messageboxaddr
    }
    return;
}

void* original_fix_menu_hook = nullptr;

void __declspec(safebuffers)fix_menu_hook()
{
    int r_esi;int r_eax;
    int r_ebx;int r_ecx;
    int r_edx;int r_edi;
    _asm
    {
        mov r_esi, esi
        mov r_eax, eax
        mov r_ebx, ebx
        mov r_ecx, ecx
        mov r_edx, edx
    }

    if (r_edx >= bad_menu_addr || r_edx < good_menu_addr)
        r_edx = good_menu_addr;

    _asm
    {
        mov eax, r_eax
        mov ebx, r_ebx
        mov ecx, r_ecx
        mov edx, r_edx
        mov esi, r_esi
        mov edi, r_edi
        leave
        mov edi, dword ptr ds : [edx]
        mov eax, dword ptr ds : [0x421A73CC]  // cheat_base + 0x7873CC
        jmp menu_ret
    }
}

void* original_xor_hook = nullptr;

int xor_hook()
{
    return 0;
}

void* original_dll_main = nullptr;

BOOL __stdcall hk_dll_main(HMODULE mod, DWORD res, LPVOID reserve)
{ 
    printf(sk("\n[  t.me/yowablog  ] [ INFO ] Setup modules...\n"));

    // set up table
    *reinterpret_cast<uintptr_t**>(cheat_base + 0x007880E0) = new uintptr_t[0x200 / sizeof(uintptr_t)];
    *reinterpret_cast<uintptr_t*>(cheat_base + 0x007880E0 + 16) = 0x40;
    *reinterpret_cast<uintptr_t*>(cheat_base + 0x007880E0 + 12) = 0x3F;
    *reinterpret_cast<uintptr_t*>(cheat_base + 0x007880E0 + 4) = *reinterpret_cast<uintptr_t*>(cheat_base + 0x007880E0);
    *reinterpret_cast<uintptr_t*>(cheat_base + 0x007880E0 + 8) = *reinterpret_cast<uintptr_t*>(cheat_base + 0x007880E0);

    game_modules_t** table = *reinterpret_cast<game_modules_t***>(cheat_base + 0x007880E0);

    memcpy(table, sk("what are you looking for fuckboy"), sizeof(sk("what are you looking for fuckboy")));

    for (const auto& modules : g_modules)
    {
        auto& parsed_data = modules.game_mod;
        table[modules.idx] = new game_modules_t;
        game_modules_t* element = reinterpret_cast<game_modules_t*>(table[modules.idx]);
        element->mod = GetModuleHandleA(parsed_data.mod.c_str());
        element->hash = parsed_data.hash;
    }

    // link table
    for (const auto& modules : g_modules)
    {
        auto& parsed_data = modules.game_mod;

        game_modules_t* data = reinterpret_cast<game_modules_t*>(table[modules.idx]);

        data->next_idx = reinterpret_cast<uintptr_t>(table[parsed_data.next_idx]);
        data->prev_idx = reinterpret_cast<uintptr_t>(table[parsed_data.prev_idx]);
    }

    printf(sk("[  t.me/yowablog  ] [ INFO ] Modules table 0x%X\n"), table);

    //
    uintptr_t** bad_hoe = (uintptr_t**)(cheat_base + 0x00788124);
    memcpy(bad_hoe, "\x58\x32\x98\x41\x53\x00\x00\x00\x40\x6D\x12\x42\x40\x7D\x12\x42\x40\x7D\x12\x42\xFF\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00", sizeof("\x58\x32\x98\x41\x53\x00\x00\x00\x40\x6D\x12\x42\x40\x7D\x12\x42\x40\x7D\x12\x42\xFF\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00"));
    bad_hoe[0] = new uintptr_t[2];
    bad_hoe[0][0] = (uintptr_t)new uintptr_t[2];
    bad_hoe[0][1] = (uintptr_t)new uintptr_t[2];

    bad_hoe[2] = new uintptr_t[0x1000];
    bad_hoe[3] = bad_hoe[2];
    bad_hoe[4] = bad_hoe[2];
    for (int i = 0; i < 0x1000; i++)
    {
        bad_hoe[2][i] = (uintptr_t)bad_hoe[0];
    }
    //

    std::map<uintptr_t, hook_info_t*> hooks;
    hook_info_t** table_hook_data = (hook_info_t**)bad_hoe[2];
    for (const auto& elem : g_hooks_data)
    {
        table_hook_data[elem.idx] = new hook_info_t;
        *table_hook_data[elem.idx] = elem.data;
        hooks[elem.data.hk - cheat_base] = table_hook_data[elem.idx];
    }

    for (const auto& elem : g_hooks_data)
    {
        auto table_elem = table_hook_data[elem.idx];
        table_elem->next = (uintptr_t)table_hook_data[table_elem->next];
        table_elem->prev = (uintptr_t)table_hook_data[table_elem->prev];
    }

    printf(sk("[  t.me/yowablog  ] [ INFO ] Init shit...\n"));

    auto key = *reinterpret_cast<uintptr_t*>(cheat_base + 0x0078629C);

    for (const auto& offsets : g_offsets)
    {
        uintptr_t fs_value = __readfsdword(0x20);
        *reinterpret_cast<uintptr_t*>(offsets.rva + cheat_base) = key ^ fs_value ^ offsets.xor2 ^ offsets.result;
    }

    *reinterpret_cast<uintptr_t*>(cheat_base + 0x8CDA40) = reinterpret_cast<uintptr_t>(GetModuleHandleA(sk("client.dll"))) + 0x3DCF30; // fix mask changer IDA( 55 8B EC 83 EC 18 53 8B D9 8D 45 04 8B 08 56 57 8B B3 ?? ?? ?? ?? 89 5D F8 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? B9 02 00 00 00 E8 ?? ?? ?? ?? 8B 8B ?? ?? ?? ?? 83 F9 FF 0F 84 ?? ?? ?? ?? 0F B7 C1 )

    ((void(*)())(cheat_base + 0x923810))(); // i forgot, mb chams
    ((void(*)())(cheat_base + 0x915000))();

    uintptr_t lol = cheat_base + 0x8C9124;
    _asm { mov ecx, lol };
    ((void(*)())(cheat_base + 0x915470))();  // init threads

    //uintptr_t kek = cheat_base + 0x16A15AD;
    //_asm { push kek };
    //((void(*)())(cheat_base + 0x51FE30))();  // init event manager

    //((void(*)())(cheat_base + 0x120460))();  // init kit parser

    printf(sk("[  t.me/yowablog  ] [ INFO ] Init fonts...\n"));

    DWORD font_shit = 1;
    HANDLE font = AddFontMemResourceEx(rawData, sizeof(rawData), 0, &font_shit);
    if (font == 0)
        MessageBoxA(0, sk("Failed load font!"), sk("Local Error"), MB_OK);

    printf(sk("[  t.me/yowablog  ] [ INFO ] Setup hooks...\n"));

    int total_hooks = 0;

    for (const auto& hk : g_hooks)
    {
        uint8_t* addr = 0;
        uintptr_t cheat_addr = 0;
        if (hk.offset == 0x237D80)
        {
            addr = (uint8_t*)(GetProcAddress(GetModuleHandleA(hk.mod), sk("GetModuleHandleExA")));
            cheat_addr = hk.offset + cheat_base;
        }
        else
        {
            addr = util::pattern_scan(hk.mod, hk.pattern);
            cheat_addr = hk.offset + cheat_base;
        }

        uintptr_t hook_rva = (uintptr_t)addr - (uintptr_t)(GetModuleHandleA(hk.mod));

        if (hooks.find(hk.offset) == hooks.end())
            MessageBoxA(0, sk("shit"), sk("1"), 0);

        auto element_table = hooks[hk.offset];
        element_table->hk = cheat_addr;
        element_table->hk2 = cheat_addr;
        MH_CreateHook(reinterpret_cast<void*>(addr), (LPVOID)cheat_addr, (LPVOID*)&element_table->trampoline);
        total_hooks++;
    }

    printf(sk("[  t.me/yowablog  ] [ INFO ] Created %d hooks\n"), total_hooks);

    memcpy((void*)(cheat_base + 0x29C5D5), "\xBE\x40\xA4\x19\x00\x90", 0x6);
    memcpy((void*)(cheat_base + 0x8B91E0), "\x50\x01\x00\x00", 0x4);

    LPVOID menu_table = VirtualAlloc(0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(menu_table, "\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00\x09\x00\x00\x00\x0A\x00\x00\x00\x0B\x00\x00\x00\x0D\x00\x00\x00\x0E\x00\x00\x00\x10\x00\x00\x00\x11\x00\x00\x00\x13\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x19\x00\x00\x00\x1A\x00\x00\x00\x1B\x00\x00\x00\x1C\x00\x00\x00\x1D\x00\x00\x00\x1E\x00\x00\x00\x20\x00\x00\x00\x21\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x26\x00\x00\x00\x27\x00\x00\x00\x28\x00\x00\x00\x3C\x00\x00\x00\x3D\x00\x00\x00\x3F\x00\x00\x00\x40\x00\x00\x00\xF4\x01\x00\x00\xF7\x01\x00\x00\xF9\x01\x00\x00\xFA\x01\x00\x00\xFB\x01\x00\x00\xFC\x01\x00\x00\xFD\x01\x00\x00\x00\x02\x00\x00\x02\x02\x00\x00\x03\x02\x00\x00\x04\x02\x00\x00\x05\x02\x00\x00\x06\x02\x00\x00\x07\x02\x00\x00\x08\x02\x00\x00\x09\x02\x00\x00\x0A\x02\x00\x00\x0B\x02\x00\x00\x0D\x02\x00\x00\x75\x12\x00\x00\xA3\x13\x00\x00\xA6\x13\x00\x00\xA7\x13\x00\x00\xA8\x13\x00\x00\xA9\x13\x00\x00\xAA\x13\x00\x00\xAB\x13\x00\x00\x00\x00\x00\x00\x00\x00\x40\xFF\xFF\xFF\x96\x00", 0x100);
    *reinterpret_cast<uintptr_t*>(cheat_base + 0x8B24C0) = reinterpret_cast<uintptr_t>(menu_table);
    bad_menu_addr = reinterpret_cast<uintptr_t>(menu_table) + 0xF0;
    good_menu_addr = reinterpret_cast<uintptr_t>(menu_table);
    memset((void*)(cheat_base + 0x1E1B03), 0x90, 0x2);

    memcpy((void*)(cheat_base + 0x22770B), "\xB8\x76\xF5\x25\x05\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90", 0x12);  // nu ok...
    memcpy((void*)(cheat_base + 0x1AFCCC), "\xE9\xE3\x01\x00\x00\x90", 0x6);  // fix eshe odin pizdec

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
        MessageBoxA(0, sk("Failed enable hooks!"), sk("Local Error"), MB_OK);

    printf("lol!\n");

    return 1;
}

fatality_t::fatality_t(HMODULE mod)
{
    AllocConsole();
    freopen_s(reinterpret_cast<FILE**>(stdin), "CONIN$", "r", stdin);
    freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);
    SetConsoleTitleA(sk("t.me/yowablog"));
    HRSRC res = FindResourceA(mod, (LPCSTR)0x65, sk("GOVNO"));
    HGLOBAL load = LoadResource(mod, res);
    size = SizeofResource(mod, res);
    resource = reinterpret_cast<uint32_t>(LockResource(load));
}

void fatality_t::relocate()
{
    printf(sk("[  t.me/yowablog  ] [ MAP ] Relocate memory...\n"));
    base = cheat_base; VirtualAlloc((LPVOID)cheat_base, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    MEMORY_BASIC_INFORMATION mem;
    if (!VirtualQuery((LPCVOID)cheat_base, &mem, sizeof(mem)))
    {
        MessageBoxA(0, sk("Inject steam.dll in steam.exe!"), sk("RATIO DETECTED!!"), MB_OK);
        ExitThread(0);
    }
    else
    {
        memcpy(reinterpret_cast<void*>(base), reinterpret_cast<void*>(resource), size);
        printf(sk("[  t.me/yowablog  ] [ MAP ] Relocated memory!\n"));
    }
}

void fatality_t::fix_imports()
{
    printf(sk("[  t.me/yowablog  ] [ MAP ] Relocate imports...\n"));
    for (const auto& imp : g_imports)
    {
        if (imp.type == type::iat)
        {
            *reinterpret_cast<uintptr_t*>(cheat_base + imp.offset) = reinterpret_cast<uintptr_t>(GetProcAddress(LoadLibraryA(imp.mod.c_str()), imp.func.c_str()));
        }
        else
        {
            uintptr_t calc = reinterpret_cast<uintptr_t>(GetProcAddress(LoadLibraryA(imp.mod.c_str()), imp.func.c_str())) - (imp.offset + base) - 0x5;
            *reinterpret_cast<uintptr_t*>(base + imp.offset + 0x1) = calc;
        }
    }
    printf(sk("[  t.me/yowablog  ] [ MAP ] Relocated imports!\n"));
}

void fatality_t::setup_hooks()
{
    if (MH_Initialize() != MH_OK)
        return;

    if (MH_CreateHook(reinterpret_cast<void*>(cheat_base + 0x00024BC0), hk_dll_main, &original_dll_main) != MH_OK)
        printf(sk("[  t.me/yowablog  ] [ HOOK ] Failed hook 1!\n"));

    if (MH_CreateHook(reinterpret_cast<void*>(cheat_base + 0x0054FDD0), xor_hook, &original_xor_hook) != MH_OK)
        printf(sk("[  t.me/yowablog  ] [ HOOK ] Failed hook 2!\n"));

    if (MH_CreateHook(reinterpret_cast<void*>(cheat_base + 0x00550040), xor_hook, &original_xor_hook) != MH_OK)
        printf(sk("[  t.me/yowablog  ] [ HOOK ] Failed hook 3!\n"));

    if (MH_CreateHook(reinterpret_cast<void*>(cheat_base + 0x001E1AB5), fix_menu_hook, &original_fix_menu_hook) != MH_OK)
        printf(sk("[  t.me/yowablog  ] [ HOOK ] Failed hook 4!\n"));

    if (MH_CreateHook(reinterpret_cast<void*>(cheat_base + 0x005A71E0), unsafe_script_hook, &original_unsafe_script) != MH_OK)
        printf(sk("[  t.me/yowablog  ] [ HOOK ] Failed hook 5!\n"));

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
        return;
}

void fatality_t::patches()
{
    events_listener_alloc = VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(events_listener_alloc, "\xDC\x9A\x0F\x42\x28\x32\x00\x00\x8C\x18\x00\x00\x04\x2E\x00\x00\xB4\x18\x00\x00\xE0\x36\x00\x00\xA4\x18\x00\x00\x30\x11\x00\x00\x20\x16\x79\x65\xFF\xB9\x00\x88", 0x28);

    memcpy((void*)(base + 0x39B120), "\x55\x89\xE5\x53\x57", 0x5);

    for (const auto& nops : g_nops)
    {
        memset((void*)(base + nops.rva), 0x90, nops.len);
    }

    memset((void*)(base + 0x2A8FB0), 0x90, 0x2);

    // fix VM pizdec =)))
    memset((void*)(cheat_base + 0x1A2854), 0x90, 0x23c);
}

void fatality_t::entry()
{
    ((void(_stdcall*)(HMODULE, DWORD, LPVOID))(entrypoint))(0, 1, reinterpret_cast<HMODULE>(cheat_base));
}

void fatality_t::meme() 
{
    shit = GetCurrentProcessId() ^ 0x811C9DC5;
    memcpy((void*)(get_pid), &shit, 0x4);

    printf(sk("[  t.me/yowablog  ] [ MAP ] Done magic!\n"));
}

void core(HMODULE mod)
{
    AddVectoredExceptionHandler(false, ExceptionHandler);

    fatality_t* cheat = new fatality_t(mod);

    cheat->relocate();
    cheat->meme();
    cheat->patches();
    cheat->setup_hooks();
    while (GetModuleHandleA(sk("serverbrowser.dll")) == 0);
    cheat->fix_imports();
    cheat->entry();

}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)core, hModule, 0, 0);
    }

    return 1;
}

