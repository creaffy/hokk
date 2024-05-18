# hokk

Modern C++ Single-Header Hooking Library For Windows (x64 and x86)

## Usage

**hk::create(Target, Detour)** adds a hook to the list but doesn't enable it.

**hk::enables(Target)** enables an existing hook.

**hk::disables(Target)** disables an existing hook.

**hk::instant(Target, Detour)** creates and instantly enables a hook.

**hk::destroy(Target)** disables and removes a hook from the list.

**hk::change(Target, Detour)** destroys and instanly creates a new hook with a new detour.

**hk::call(Target, Args...)** calls the original function.

**hk::exists(Target)** checks if a hook exists.

**hk::status(Target)** checks if a hook exists and if it's enabled.

## How It Works

This library is basically the simplest hooking library possible. It temporarily enables write permissions for the memory location target is in and inserts the following assembly instructions at the start of the function (x64/x86):

```
movabs rax, DETOUR
jmp rax
```

```
mov eax, DETOUR
jmp eax
```

This is much different from the trampoline mechanism libraries like [MinHook](https://github.com/TsudaKageyu/minhook) use, so in order to call the original function, the hook must be disabled and then re-enabled.

## Example

```cpp
int __declspec(noinline) A(int x, int y) { return x*y; };
int __declspec(noinline) B(int x, int y) { return 777; };
int __declspec(noinline) C(int x, int y) { return 420; };

int main() {
    hk::instant(A, B);

    std::println("{}", A(30, 9));           // 777 (B is called)
    std::println("{}", hk::call(A, 30, 9)); // 270 (A is called)

    hk::change(A, C);

    std::println("{}", A(69, 2));           // 420 (C is called)
    std::println("{}", hk::call(A, 69, 2)); // 138 (A is called)

    hk::destroy(A);

    std::println("{}", A(6, 53));           // 318 (A is called)
}
```
