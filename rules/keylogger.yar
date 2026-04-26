rule Keylogger_Strings {
    strings:
        $s1 = "SetWindowsHookEx" nocase
        $s2 = "GetAsyncKeyState" nocase
        $s3 = "GetKeyState" nocase
        $s4 = "keylog" nocase
        $s5 = "keyboard_hook" nocase
        $s6 = "intercept_keys" nocase

    condition:
        any of them
}
