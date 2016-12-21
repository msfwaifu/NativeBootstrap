/*
    Initial author: (https://github.com/)Convery for Ayria.se
    License: MIT
    Started: 2016-12-21
    Notes:
        The plugins are verified against a digital signature
        or through a global whitelist managed by the desktop.
*/

#pragma once

#include <cstdint>
#include <string>

constexpr const char *Pluginextension = sizeof(void *) == 8 ? "Ayria64" : "Ayria32";

struct Plugin
{
    bool Verified{};
    std::string Name;
    uint64_t Filehash{};
    void *OnMessagepointer{};
};
