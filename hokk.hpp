#pragma once
#include <vector>
#include <algorithm>
#include <windows.h>

namespace _hk {
#ifdef _WIN64
    // movabs rax, 0x0000000000000000
    // jmp rax
    constexpr inline unsigned char _code[12] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
#else
    // mov eax, 0x00000000
    // jmp eax
    constexpr inline unsigned char _code[7] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
#endif

    struct _hook {
        void* m_target;
        void* m_detour;
        char  m_original[sizeof(_hk::_code)];
    };

    inline std::vector<_hook> _hooks;

    inline _hook* _get(void* target) {
        auto iter = std::ranges::find_if(_hooks, [target](const _hook& e) { return e.m_target == target; });
        return iter == _hooks.end() ? nullptr : &*iter;
    }

    inline bool _remove(void* target) {
        auto iter = std::ranges::find_if(_hooks, [target](const _hook& e) { return e.m_target == target; });
        if (iter == _hooks.end())
            return false;
        _hooks.erase(iter);
        return true;
    }

    inline bool _add(const _hook& context) {
        if (_hk::_get(context.m_target))
            return false;
        _hooks.push_back(context);
        return true;
    }

    inline bool _status(const _hook& context) {
        for (auto i = 0; i < sizeof(_hk::_code); ++i) {
            if (context.m_original[i] != reinterpret_cast<char*>(context.m_target)[i])
                return true;
        }
        return false;
    }

    inline DWORD _protect(const _hook& context, DWORD flags) {
        DWORD old = -1;
        VirtualProtect(context.m_target, sizeof(_hk::_code), flags, &old);
        return old;
    }
}

namespace hk {
    template <class T>
    inline bool exists(T&& target) {
        auto context = _hk::_get(reinterpret_cast<void*>(target));
        return context;
    }

    template <class T>
    inline bool status(T&& target) {
        auto context = _hk::_get(reinterpret_cast<void*>(target));
        return context && _hk::_status(*context);
    }

    template <class T>
    inline bool enable(T&& target) {
        auto context = _hk::_get(reinterpret_cast<void*>(target));
        if (!context)
            return false;
        auto old = _hk::_protect(*context, PAGE_EXECUTE_READWRITE);
        if (old == -1)
            return false;
        std::memcpy(context->m_target, _hk::_code, sizeof(_hk::_code));
#ifdef _WIN64
        std::memcpy(reinterpret_cast<char*>(context->m_target) + 2, &context->m_detour, 8);
#else
        std::memcpy(reinterpret_cast<char*>(context->m_target) + 1, &context->m_detour, 4);
#endif
        if (_hk::_protect(*context, old) == -1)
            return false;
        return true;
    }

    template <class T>
    inline bool disable(T&& target) {
        auto context = _hk::_get(reinterpret_cast<void*>(target));
        if (!context)
            return false;
        auto old = _hk::_protect(*context, PAGE_EXECUTE_READWRITE);
        if (old == -1)
            return false;
        std::memcpy(context->m_target, context->m_original, sizeof(_hk::_code));
        if (_hk::_protect(*context, old) == -1)
            return false;
        return true;
    }

    template <class T, class... A>
    inline auto call(T&& target, A&&... args) {
        auto rehook = hk::status(target);
        hk::disable(target);
        if constexpr (std::is_same_v<decltype(target(std::forward<A>(args)...)), void>) {
            target(std::forward<A>(args)...);
            if (rehook)
                hk::enable(target);
        }
        else {
            auto retval = target(std::forward<A>(args)...);
            if (rehook)
                hk::enable(target);
            return retval;
        }
    }

    template <class T, class D>
    inline bool create(T&& target, D&& detour) {
        if (!target || !detour)
            return false;
        _hk::_hook context{};
        context.m_target = reinterpret_cast<void*>(target);
        context.m_detour = reinterpret_cast<void*>(detour);
        std::memcpy(context.m_original, context.m_target, sizeof(_hk::_code));
        return _hk::_add(context);
    }

    template <class T>
    inline bool destroy(T&& target) {
        return hk::disable(target) && _hk::_remove(reinterpret_cast<void*>(target));
    }

    template <class T, class D>
    inline bool instant(T&& target, D&& detour) {
        return hk::create(target, detour) && hk::enable(target);
    }

    template <class T, class D>
    inline bool change(T&& target, D&& detour) {
        return hk::destroy(target) && hk::instant(target, detour);
    }
}
