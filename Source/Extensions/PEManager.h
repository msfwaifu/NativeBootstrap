/*
    Initial author: (https://github.com/)Convery for Ayria.se
    License: MIT
    Started: 2016-12-21
    Notes:
        The loading methods are exposed via Dllmain.cpp
*/

#pragma once

#include "Plugin.h"
#include <vector>

struct PEManager
{
    static std::vector<Plugin> Loadedplugins;

    static void Unload(const char *Filepath);
    static void Load(const char *Filepath);
    static void Unloadall();
    static void Loadall();
};
