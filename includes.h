#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "minhook/minhook.h"
#include "utils.h"
#include <cstdint>
#include <intrin.h>
#include <iostream>
#include <map>
#include "crypt.h"

enum type
{
	call = 0,
	jmp = 1,
	iat = 2
};

struct shit_t
{
	uintptr_t hash;
	std::string module;
};

static std::vector < shit_t > g_shit = {
{ 0xfc70fd90, "localize.dll" },
{ 0x38450191, "engine.dll" },
{ 0x4da4ce6a, "filesystem_stdio.dll" },
{ 0x990704d7, "vstdlib.dll" },
{ 0x35153f28, "panorama.dll" },
{ 0x6c5a4374, "client.dll" },
{ 0x87f9fb5b, "materialsystem.dll" },
{ 0x3f8d8a40, "vgui2.dll" },
{ 0x97ac4c4,  "vphysics.dll" },
{ 0x19c2e8fc, "gameoverlayrenderer.dll" },
{ 0xd0849acf, "vguimatsurface.dll" },
{ 0xe40e165d, "studiorender.dll" },
{ 0xe26d30e8, "server.dll" },
{ 0x2935fa11, "tier0.dll" },
{ 0x91982ef,  "datacache.dll" },
{ 0x4943f878, "inputsystem.dll" },
{ 0x293f84bd, "shaderapidx9.dll" },
{ 0x45436709, "v8.dll" },
};
