// Shell command segment analysis — chain splitting, safe-arg detection, pattern matching.

const std = @import("std");

// --- Internal tables (detection mechanics, not policy rules) ---

pub const chain_separators = [_][]const u8{ "&&", "||", ";", "$(", "`", "|", "\n", "(", "{" };

// Commands whose arguments are safe (search patterns, display text, etc.)
// For these commands, only the command name itself matters, not args.
// NOT included: sed (e flag executes), awk (system() executes), perl, python, ruby, etc.
const safe_arg_commands = [_][]const u8{
    "echo",  "printf", "print",
    "grep",  "egrep",  "fgrep", "rg", "ag", "ack",
    "test",  "[",
    "git log", "git show", "git diff", "git grep",
    // Metadata-only commands (args are file paths, output is metadata not content)
    "ls", "stat", "file", "wc", "du", "md5sum", "sha256sum",
    "diff", "cmp", "comm",
    "which", "type", "whereis",
    // NOTE: find is handled separately in isSafeArgCommand (safe only without -exec/-delete)
};

// --- Generic pattern matching ---

pub fn containsPattern(haystack: []const u8, patterns: []const []const u8) bool {
    for (patterns) |pattern| {
        if (std.mem.indexOf(u8, haystack, pattern) != null) return true;
    }
    return false;
}

// --- Shell prefix stripping ---

// Strip transparent shell prefixes: "command ", "builtin ", and leading VAR=val assignments
pub fn stripShellPrefix(segment: []const u8) []const u8 {
    var trimmed = std.mem.trimLeft(u8, segment, " \t\n\r");
    // Strip leading VAR=val assignments (e.g., "X=1 Y=2 eval ...")
    while (trimmed.len > 0) {
        // Check for NAME=VALUE pattern: starts with letter/underscore, has = before space
        if ((std.ascii.isAlphabetic(trimmed[0]) or trimmed[0] == '_')) {
            if (std.mem.indexOfAny(u8, trimmed, "= \t")) |first| {
                if (first < trimmed.len and trimmed[first] == '=') {
                    // Found VAR=, skip to after the value
                    const after_eq = trimmed[first + 1 ..];
                    const val_end = std.mem.indexOfAny(u8, after_eq, " \t") orelse after_eq.len;
                    if (first + 1 + val_end < trimmed.len) {
                        trimmed = std.mem.trimLeft(u8, after_eq[val_end..], " \t");
                        continue;
                    } else {
                        // VAR=val is the entire segment, no command follows
                        return trimmed;
                    }
                }
            }
        }
        break;
    }
    // Strip transparent wrapper prefixes (command/builtin/nohup/time/watch)
    // Loop to handle multiple levels: e.g. "nohup command eval ..." → "eval ..."
    const transparent = [_][]const u8{
        "command ", "builtin ", "nohup ", "time ", "watch ",
        // Shell keywords that introduce command lists (not commands themselves)
        "then ", "do ", "else ", "elif ",
    };
    var changed = true;
    while (changed) {
        changed = false;
        for (transparent) |prefix| {
            if (std.mem.startsWith(u8, trimmed, prefix)) {
                trimmed = std.mem.trimLeft(u8, trimmed[prefix.len..], " \t");
                changed = true;
                break;
            }
        }
    }
    return trimmed;
}

// --- Segment matching ---

fn isExactOrPrefixMatch(command: []const u8, patterns: []const []const u8) bool {
    const trimmed = stripShellPrefix(command);
    for (patterns) |pattern| {
        if (std.mem.eql(u8, trimmed, pattern)) return true;
        if (std.mem.startsWith(u8, trimmed, pattern) and pattern[pattern.len - 1] == ' ') return true;
        if (std.mem.startsWith(u8, trimmed, pattern) and trimmed.len > pattern.len and std.ascii.isWhitespace(trimmed[pattern.len])) return true;
    }
    return false;
}

// Check if a segment starts with a safe-arg command
fn isSafeArgCommand(segment: []const u8) bool {
    const trimmed = stripShellPrefix(segment);

    // find is safe only without -exec/-execdir/-ok/-delete
    if (std.mem.startsWith(u8, trimmed, "find") and
        (trimmed.len == 4 or (trimmed.len > 4 and std.ascii.isWhitespace(trimmed[4]))))
    {
        const dangerous_find_flags = [_][]const u8{ "-exec", "-execdir", "-ok", "-delete" };
        for (dangerous_find_flags) |flag| {
            if (std.mem.indexOf(u8, trimmed, flag) != null) return false;
        }
        return true;
    }

    for (safe_arg_commands) |cmd| {
        if (std.mem.startsWith(u8, trimmed, cmd)) {
            if (trimmed.len == cmd.len or
                (trimmed.len > cmd.len and std.ascii.isWhitespace(trimmed[cmd.len])))
            {
                return true;
            }
        }
    }
    return false;
}

// --- Chain segment iterator ---

pub const ChainIterator = struct {
    remaining: []const u8,
    separators: []const []const u8,

    pub fn next(self: *ChainIterator) ?[]const u8 {
        if (self.remaining.len == 0) return null;
        var earliest: ?usize = null;
        var sep_len: usize = 0;
        for (self.separators) |sep| {
            if (std.mem.indexOf(u8, self.remaining, sep)) |idx| {
                if (earliest == null or idx < earliest.?) {
                    earliest = idx;
                    sep_len = sep.len;
                }
            }
        }
        const segment = if (earliest) |idx| self.remaining[0..idx] else self.remaining;
        if (earliest) |idx| {
            self.remaining = self.remaining[idx + sep_len ..];
        } else {
            self.remaining = self.remaining[self.remaining.len..];
        }
        return segment;
    }
};

pub fn chainSegments(command: []const u8) ChainIterator {
    return .{ .remaining = command, .separators = &chain_separators };
}

// --- Env dump detection ---

fn isEnvDumpSegment(segment: []const u8) bool {
    // Trim whitespace and trailing ')' from subshell syntax, then strip command/builtin prefix
    const trimmed = stripShellPrefix(std.mem.trim(u8, std.mem.trimRight(u8, std.mem.trim(u8, segment, " \t\n\r"), ")"), " \t\n\r"));
    // "env" exactly (dump all env vars)
    if (std.mem.eql(u8, trimmed, "env")) return true;
    // "env" + whitespace → parse args to determine if a command follows
    if (std.mem.startsWith(u8, trimmed, "env") and trimmed.len > 3 and std.ascii.isWhitespace(trimmed[3])) {
        // Skip past flags (-x, -u VAR) and VAR=val assignments to find a command
        var rest = std.mem.trimLeft(u8, trimmed[4..], " \t");
        while (rest.len > 0) {
            if (rest[0] == '-') {
                const end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
                const flag = rest[0..end];
                rest = std.mem.trimLeft(u8, rest[end..], " \t");
                const flags_with_arg = [_][]const u8{ "-u", "--unset", "-S", "--split-string", "-C", "--chdir" };
                var takes_arg = false;
                for (flags_with_arg) |fa| {
                    if (std.mem.eql(u8, flag, fa)) {
                        takes_arg = true;
                        break;
                    }
                }
                if (takes_arg and rest.len > 0) {
                    const arg_end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
                    rest = std.mem.trimLeft(u8, rest[arg_end..], " \t");
                }
            } else if (std.mem.indexOf(u8, rest, "=")) |eq_idx| {
                const sp_idx = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
                if (eq_idx < sp_idx) {
                    rest = std.mem.trimLeft(u8, rest[sp_idx..], " \t");
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
        return true;
    }
    return false;
}

pub fn isEnvDump(command: []const u8) bool {
    var it = chainSegments(command);
    while (it.next()) |segment| {
        if (isEnvDumpSegment(segment)) return true;
    }
    return false;
}

// --- Chain-aware matching ---

pub fn matchesPrefixInChain(command: []const u8, patterns: []const []const u8) bool {
    var it = chainSegments(command);
    while (it.next()) |segment| {
        if (isExactOrPrefixMatch(segment, patterns)) return true;
    }
    return false;
}

// Count chain segments (for excessive chaining detection)
// Only count && and || — semicolons excluded because normalizeShellEvasion
// strips quotes, causing semicolons inside quoted strings to be miscounted
pub fn countChainSegments(command: []const u8) usize {
    const major_separators = [_][]const u8{ "&&", "||" };
    var it = ChainIterator{ .remaining = command, .separators = &major_separators };
    var count: usize = 0;
    while (it.next()) |_| count += 1;
    return count;
}

// Check if a pattern exists in any NON-safe-arg segment of a chained command
pub fn containsPatternSafe(command: []const u8, patterns: []const []const u8) bool {
    var it = chainSegments(command);
    while (it.next()) |segment| {
        if (!isSafeArgCommand(segment)) {
            if (containsPattern(segment, patterns)) return true;
        }
    }
    return false;
}

// --- git push detection (robust to global options) ---

// git global options that consume the FOLLOWING token as their argument.
// Without skipping the arg, a value like `-c key=val` would be mistaken for
// the subcommand. The `=`-attached forms (--git-dir=...) are single tokens
// and handled by the generic "starts with -" skip below.
const git_opts_with_arg = [_][]const u8{
    "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env",
};

// `env` options that consume the FOLLOWING token as their argument.
const env_opts_with_arg = [_][]const u8{ "-u", "--unset", "-C", "--chdir" };

fn eqlAny(tok: []const u8, list: []const []const u8) bool {
    for (list) |o| {
        if (std.mem.eql(u8, tok, o)) return true;
    }
    return false;
}

// A push argument that forces history rewrite: --force, --force-with-lease,
// --force-if-includes, single-dash short bundles containing 'f' (-f, -fv),
// and a leading-`+` refspec (`+main`, `+HEAD:refs/...`) which force-updates
// that ref.
fn isForcePushFlag(tok: []const u8) bool {
    if (std.mem.startsWith(u8, tok, "--force")) return true;
    if (tok.len >= 2 and tok[0] == '-' and tok[1] != '-') {
        if (std.mem.indexOfScalar(u8, tok, 'f') != null) return true;
    }
    if (tok.len >= 2 and tok[0] == '+') return true;
    return false;
}

const EnvTokenIterator = std.mem.TokenIterator(u8, .any);

// Skip a leading `env [-opts] [VAR=val]...` wrapper and return the wrapped
// command token (e.g. `git`), or null if env wraps nothing. `git` is not a
// stripShellPrefix transparent prefix because env takes its own options, so
// `env git push --force` would otherwise be parsed with first token "env".
fn skipEnvWrapper(it: *EnvTokenIterator) ?[]const u8 {
    while (it.next()) |tok| {
        if (tok.len == 0) continue;
        if (tok[0] == '-') {
            if (eqlAny(tok, &env_opts_with_arg)) _ = it.next();
            continue;
        }
        // VAR=val assignment (NAME starts alpha/_ and contains '=') — keep skipping.
        if ((std.ascii.isAlphabetic(tok[0]) or tok[0] == '_') and std.mem.indexOfScalar(u8, tok, '=') != null) {
            continue;
        }
        return tok;
    }
    return null;
}

// Last path component, so `/usr/bin/git` is recognised as `git`.
fn commandBasename(tok: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, tok, '/')) |i| return tok[i + 1 ..];
    return tok;
}

const GitPush = struct { push: bool, force: bool };

// Parse a single (already chain-split) segment and report whether it invokes
// `git push` with git global options (-C <path>, -c <cfg>, --git-dir=...)
// skipped, and if so whether a force flag is present. This defeats the
// `git -C <path> push` bypass of the contiguous "git push" substring.
fn parseGitPushSegment(segment: []const u8) GitPush {
    const no_push = GitPush{ .push = false, .force = false };
    const trimmed = stripShellPrefix(segment);
    var it = std.mem.tokenizeAny(u8, trimmed, " \t");
    var first = it.next() orelse return no_push;
    // Unwrap leading `env [opts] [VAR=val]...` wrappers (including nested
    // `env env git push`) so the real git invocation is seen.
    while (std.mem.eql(u8, commandBasename(first), "env")) {
        first = skipEnvWrapper(&it) orelse return no_push;
    }
    if (!std.mem.eql(u8, commandBasename(first), "git")) return no_push;

    // Walk past git global options to the subcommand token.
    var sub: ?[]const u8 = null;
    while (it.next()) |tok| {
        if (tok.len > 0 and tok[0] == '-') {
            if (eqlAny(tok, &git_opts_with_arg)) _ = it.next();
            continue;
        }
        sub = tok;
        break;
    }
    if (sub == null or !std.mem.eql(u8, sub.?, "push")) return no_push;

    var force = false;
    while (it.next()) |tok| {
        if (isForcePushFlag(tok)) force = true;
    }
    return .{ .push = true, .force = force };
}

// True if any non-safe-arg segment runs `git push` (force or not).
pub fn hasGitPush(command: []const u8) bool {
    var it = chainSegments(command);
    while (it.next()) |segment| {
        if (!isSafeArgCommand(segment) and parseGitPushSegment(segment).push) return true;
    }
    return false;
}

// True if any non-safe-arg segment runs `git push` with a force flag.
pub fn hasGitForcePush(command: []const u8) bool {
    var it = chainSegments(command);
    while (it.next()) |segment| {
        if (!isSafeArgCommand(segment)) {
            const g = parseGitPushSegment(segment);
            if (g.push and g.force) return true;
        }
    }
    return false;
}

// --- recursive rm target-aware whitelist ---

fn commandIsRm(tok: []const u8) bool {
    return std.mem.eql(u8, commandBasename(tok), "rm");
}

// A recursive-delete flag: --recursive, or a single-dash bundle containing
// r/R in ANY position (-r, -rf, -vr, -fvr, -Rf). Long options other than
// --recursive are not recursive.
fn isRecursiveRmFlag(tok: []const u8) bool {
    if (std.mem.eql(u8, tok, "--recursive")) return true;
    if (tok.len >= 2 and tok[0] == '-' and tok[1] != '-') {
        return std.mem.indexOfAny(u8, tok, "rR") != null;
    }
    return false;
}

// True if `target` is a literal path safe to recursively delete. Rejects
// $VAR/$( ), globs, ~, and any `..` path component. Then allows either an
// absolute path UNDER a temp dir (/tmp/x, /var/tmp/x — never the bare temp
// root) OR a relative path whose first OR last component is an ephemeral dir.
fn isEphemeralRmTarget(
    target: []const u8,
    safe_dirs: []const []const u8,
    temp_prefixes: []const []const u8,
) bool {
    if (target.len == 0) return false;
    if (std.mem.indexOfScalar(u8, target, '$') != null) return false; // variable / cmd subst
    if (std.mem.indexOfAny(u8, target, "*?[") != null) return false; // glob
    if (target[0] == '~') return false; // home

    var t = target;
    while (t.len > 1 and t[t.len - 1] == '/') t = t[0 .. t.len - 1]; // strip trailing '/', keep lone "/"

    // Reject any `..` path component (parent traversal), absolute or relative.
    {
        var c = std.mem.tokenizeScalar(u8, t, '/');
        while (c.next()) |comp| if (std.mem.eql(u8, comp, "..")) return false;
    }

    // Absolute: only under an allowed temp dir, and only when the remainder
    // names a real subpath — a tail of just "." components (e.g. `/tmp/.`,
    // `/tmp/./.`) aliases the bare temp root and must be denied.
    if (t[0] == '/') {
        for (temp_prefixes) |p| {
            if (!std.mem.startsWith(u8, t, p) or t.len <= p.len) continue;
            var rest = std.mem.tokenizeScalar(u8, t[p.len..], '/');
            while (rest.next()) |comp| {
                if (!std.mem.eql(u8, comp, ".")) return true; // a real component
            }
            return false; // only "." components → the temp root itself
        }
        return false;
    }

    // Relative: first OR last component must be an ephemeral dir.
    while (std.mem.startsWith(u8, t, "./")) t = t[2..];
    if (t.len == 0 or std.mem.eql(u8, t, ".")) return false;
    var first: ?[]const u8 = null;
    var last: []const u8 = "";
    var comps = std.mem.tokenizeScalar(u8, t, '/');
    while (comps.next()) |comp| {
        if (first == null) first = comp;
        last = comp;
    }
    if (first == null) return false;
    return eqlAny(first.?, safe_dirs) or eqlAny(last, safe_dirs);
}

// Contiguous recursive-rm substrings. These also fire when `rm -rf ...` is
// embedded in a non-rm segment (interpreter payloads, git aliases, etc.) —
// e.g. python -c 'os.system("rm -rf /")' — which the tokenizer would miss
// because the rm is glued to a quote. segmentIsSafeEphemeralRm still gates the
// allow, so only genuinely-safe ephemeral rm is exempted.
const recursive_rm_substrings = [_][]const u8{
    "rm -r",         "rm -R",  "rm -fr",          "rm -fR",
    "rm -Ir",        "rm -IR", "rm -f -r",        "rm -f -R",
    "rm --recursive", "rm --force --recursive",
};

// True if a chain segment invokes a recursive rm anywhere in it — including
// behind wrappers (`xargs rm -rf`, `find ... -exec rm -rf`) or embedded in a
// payload string. Combines a substring scan (contiguous forms, even inside
// quotes) with a tokenizer scan (flag bundles like `-vr` the substrings miss).
fn segmentHasRecursiveRm(segment: []const u8) bool {
    if (containsPattern(segment, &recursive_rm_substrings)) return true;
    var it = std.mem.tokenizeAny(u8, segment, " \t");
    var seen_rm = false;
    while (it.next()) |tok| {
        if (!seen_rm) {
            if (commandIsRm(tok)) seen_rm = true;
            continue;
        }
        if (std.mem.eql(u8, tok, "--")) return false; // targets only past here
        if (isRecursiveRmFlag(tok)) return true;
    }
    return false;
}

// Whether a recursive-rm segment is a SAFE ephemeral deletion: a bare `rm`
// (optionally behind env wrappers) whose every target is an ephemeral relative
// dir. Wrappers that obscure the rm (xargs, sudo, an unparsed prefix) → false
// so the caller denies it.
fn segmentIsSafeEphemeralRm(
    segment: []const u8,
    safe_dirs: []const []const u8,
    temp_prefixes: []const []const u8,
) bool {
    const trimmed = stripShellPrefix(segment);
    var it = std.mem.tokenizeAny(u8, trimmed, " \t");
    var first = it.next() orelse return false;
    while (std.mem.eql(u8, commandBasename(first), "env")) {
        first = skipEnvWrapper(&it) orelse return false;
    }
    if (!commandIsRm(first)) return false;

    var end_of_opts = false;
    var target_count: usize = 0;
    while (it.next()) |tok| {
        if (!end_of_opts and std.mem.eql(u8, tok, "--")) {
            end_of_opts = true;
            continue;
        }
        if (!end_of_opts and tok.len > 0 and tok[0] == '-') continue; // flag
        target_count += 1;
        if (!isEphemeralRmTarget(tok, safe_dirs, temp_prefixes)) return false;
    }
    return target_count > 0;
}

// True if the command contains a recursive rm that is NOT a safe ephemeral
// deletion (so it must be denied). Each non-safe-arg segment with a recursive
// rm must parse as a safe ephemeral rm; otherwise it is unsafe.
pub fn unsafeRecursiveRm(
    command: []const u8,
    safe_dirs: []const []const u8,
    temp_prefixes: []const []const u8,
) bool {
    var it = chainSegments(command);
    while (it.next()) |segment| {
        if (isSafeArgCommand(segment)) continue;
        if (!segmentHasRecursiveRm(segment)) continue;
        if (!segmentIsSafeEphemeralRm(segment, safe_dirs, temp_prefixes)) return true;
    }
    return false;
}

// Check if BOTH context and payload patterns exist in the SAME non-safe-arg segment.
// Used for compound checks where cross-segment matching causes false positives (issue #41).
pub fn containsCompoundInSegment(
    command: []const u8,
    context_patterns: []const []const u8,
    payload_patterns: []const []const u8,
) bool {
    var it = chainSegments(command);
    while (it.next()) |segment| {
        if (!isSafeArgCommand(segment)) {
            if (containsPattern(segment, context_patterns) and
                containsPattern(segment, payload_patterns))
            {
                return true;
            }
        }
    }
    return false;
}
