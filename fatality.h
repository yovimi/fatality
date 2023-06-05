#pragma once
#include "includes.h"
#include "imports.h"

constexpr std::uintptr_t cheat_base = 0x41A20000;
constexpr std::uintptr_t cheat_size = 0x01FEC000;
constexpr std::uintptr_t entrypoint = cheat_base + 0x00603DB6;
constexpr std::uintptr_t dllmain = cheat_base + 0x00024BC0;
constexpr std::uintptr_t get_pid = cheat_base + 0x0078629C;
constexpr std::uintptr_t init_cheat = cheat_base + 0x00929370;
constexpr std::uintptr_t return_shit = 0x431C0045;
constexpr std::uintptr_t cheat_thread = cheat_base + 0x00621F39;
constexpr std::uintptr_t cheat_main = cheat_base + 0x00621E42;

uintptr_t bad_menu_addr = 0;
uintptr_t good_menu_addr = 0;
uintptr_t menu_ret = cheat_base + 0x1E1ABC;

void* original_shit = nullptr;
uintptr_t pushinb = cheat_base + 0x008B6640;
uintptr_t ret_shit = cheat_base + 0x00024F72;
uintptr_t retlol = 0; 
uintptr_t shit = 0;
int recv_ptr = 1;
bool recv_call = false;
int all_recv_size = 0;
LPVOID events_listener_alloc = 0;

class fatality_t
{
	std::uintptr_t base;
	std::uintptr_t size;
	std::uintptr_t resource;
public:
	fatality_t(HMODULE mod);

	void relocate();
	void fix_imports();
	void patches();
	void setup_hooks();
	void entry();
	void meme();
};