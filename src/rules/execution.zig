// Shell exploitation patterns — dangerous commands, reverse shells, pipe-to-shell, obfuscation.

// Ephemeral / regenerable directory names. A recursive rm is exempt from the
// hard deny only when EVERY target's first or last path component is one of
// these (as a literal relative path). Build outputs and caches only — never
// source dirs. Extend here to allow more no-prompt cleanups.
pub const rm_safe_dirs = [_][]const u8{
    "node_modules", "dist",          "build",         "out",
    "coverage",     "target",        ".next",         ".nuxt",
    ".svelte-kit",  ".turbo",        ".cache",        ".parcel-cache",
    ".pytest_cache", "__pycache__",  ".mypy_cache",   ".ruff_cache",
    "zig-out",      ".zig-cache",
};

// Absolute path prefixes under which recursive rm is allowed (scratch/temp
// space). The bare temp root itself is never allowed — only paths beneath it,
// and `..` traversal out of it is still rejected.
pub const rm_safe_abs_prefixes = [_][]const u8{
    "/tmp/", "/var/tmp/", "/private/tmp/", "/private/var/tmp/",
};

// Dangerous command patterns to block
pub const dangerous_commands = [_][]const u8{
    " -delete",
    "sudo ",
    "chmod 777",
    "chmod u+s",
    "chmod +s ",
    // git push --force / -f handled by shell_analyzer.hasGitForcePush
    // (robust to `git -C <path> push --force` global-option bypass)
    "git reset --hard",
    "git clean -f",
    // Credential theft
    "credential.helper",
    "git credential-",
    "git credential ",
    // Git config dangerous keys (issue #3)
    "core.hooksPath",
    "core.pager",
    "core.editor",
    "core.sshCommand",
    "mkfs",
    "dd if=",
    "> /dev/",
    "shred ",
    "truncate ",
    // Privilege escalation
    "su -",
    "su root",
    "doas ",
    "pkexec ",
    // Persistence
    "crontab ",
    "launchctl ",
    "systemctl enable",
    "systemctl start",
    // macOS specific
    "osascript ",
    "defaults write ",
    "defaults delete ",
    "diskutil ",
    "hdiutil ",
    "spctl ",
    "tccutil ",
    "codesign ",
    "dscl ",
    "PlistBuddy ",
    // Named pipe — used for IPC backdoors
    "mkfifo ",
    // Browser remote debugging / automation hijacking (issue #20)
    "--remote-debugging-port",
    "puppeteer.connect",
    "playwright.connect",
    "chrome-remote-interface",
};

// Reverse shell / code injection patterns
pub const reverse_shell_patterns = [_][]const u8{
    "/dev/tcp/",
    "/dev/udp/",
    "bash -i",
    "sh -i",
    "import socket",
    "socket.socket",
    "socket.connect",
    "use Socket",
    "SOCK_STREAM",
    "pty.spawn",
    "child_process",
    "TCPSocket",
    "fsockopen",
    "net.Socket",
    "os.dup2",
    "__import__",
};

// Shell binary names — single source of truth for pipe-to-shell, process substitution, heredoc detection
pub const shell_names = [_][]const u8{ "bash", "sh", "zsh", "dash", "fish", "ksh", "csh", "tcsh" };

// Interpreter binary names — pipe-to-interpreter detection (issue #50)
// These execute stdin as code when invoked without a script file argument.
pub const interpreter_names = [_][]const u8{ "python", "python3", "node", "ruby", "perl", "pwsh", "php", "bun", "deno" };

// Pipe-to-shell execution patterns
pub const pipe_shell_patterns = [_][]const u8{
    "| bash",
    "| sh",
    "| zsh",
    "| sudo bash",
    "| sudo sh",
    "|bash",
    "|sh",
    "|zsh",
    // Absolute path bypass prevention
    "| /bin/bash",
    "| /bin/sh",
    "| /bin/zsh",
    "| /usr/bin/bash",
    "| /usr/bin/sh",
    "| /usr/bin/zsh",
    "|/bin/bash",
    "|/bin/sh",
    "|/bin/zsh",
    "|/usr/bin/bash",
    "|/usr/bin/sh",
    "|/usr/bin/zsh",
    // Heredoc/herestring to shell (bash << also covers bash <<<)
    "bash <<",
    "sh <<",
    "zsh <<",
    "dash <<",
    "fish <<",
    "ksh <<",
    "csh <<",
    "tcsh <<",
    // No-space variants
    "bash<<<",
    "sh<<<",
    "zsh<<<",
    "dash<<<",
    "fish<<<",
    "ksh<<<",
    "csh<<<",
    "tcsh<<<",
};

// Shell obfuscation patterns (always block)
pub const shell_obfuscation_patterns = [_][]const u8{
    "$'\\x", // ANSI-C hex quoting: $'\x72\x6d' = rm
    "$'\\0", // ANSI-C octal quoting
    "$'\\u", // ANSI-C unicode escape: $'\u0072\u006d' = rm
    "@P}", // ${var@P}: Bash prompt expansion — can execute commands
};

// History evasion commands
pub const history_evasion_commands = [_][]const u8{
    "unset HISTFILE",
    "history -c",
    "history -w /dev/null",
    "HISTSIZE=0",
    "HISTFILE=",
};

// Shell builtins — dangerous at command start position
pub const shell_builtins = [_][]const u8{
    "printenv",
    "export -p",
    "eval",
    "exec",
    "security",
    "at",
    "batch",
    // Shell self-reference — $0 expands to current shell binary name
    "$0",
    // Script sourcing — executes arbitrary scripts in current shell
    "source",
    ".",
    // Coprocess — creates background shell process
    "coproc",
    // Alias definition — persistence/hijacking attack vector
    "alias ",
};
