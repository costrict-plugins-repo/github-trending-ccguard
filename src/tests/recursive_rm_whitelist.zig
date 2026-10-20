const std = @import("std");
const types = @import("../types.zig");
const evaluator = @import("../evaluator.zig");
const evaluate = evaluator.evaluate;

fn decide(cmd: []const u8) types.Decision {
    return evaluate(.{ .tool_name = "Bash", .tool_input = .{ .command = cmd } }).decision;
}

// ============================================================================
// Recursive rm target-aware whitelist
//   allow:  recursive rm whose targets are ALL ephemeral relative dirs
//   deny:   everything else (absolute incl. /tmp, ~, $VAR, globs, .., in-repo
//           non-ephemeral, no target, wrapper-obscured rm)
// ============================================================================

// --- new allow: ephemeral relative dir deletions ---

test "allow rm -rf node_modules" {
    try std.testing.expectEqual(.allow, decide("rm -rf node_modules"));
}

test "allow rm -rf ./node_modules" {
    try std.testing.expectEqual(.allow, decide("rm -rf ./node_modules"));
}

test "allow rm -rf dist" {
    try std.testing.expectEqual(.allow, decide("rm -rf dist"));
}

test "allow rm -rf build" {
    try std.testing.expectEqual(.allow, decide("rm -rf build"));
}

test "allow rm -rf zig-out (this repo)" {
    try std.testing.expectEqual(.allow, decide("rm -rf zig-out"));
}

test "allow rm -rf target trailing slash" {
    try std.testing.expectEqual(.allow, decide("rm -rf target/"));
}

test "allow rm -rf multiple ephemeral targets" {
    try std.testing.expectEqual(.allow, decide("rm -rf dist build .next"));
}

test "allow rm -rf subpath under ephemeral root" {
    try std.testing.expectEqual(.allow, decide("rm -rf node_modules/.cache"));
}

test "allow rm -rf ephemeral leaf in monorepo path" {
    try std.testing.expectEqual(.allow, decide("rm -rf packages/app/node_modules"));
}

test "allow rm -r without f on ephemeral" {
    try std.testing.expectEqual(.allow, decide("rm -r coverage"));
}

test "allow chained ephemeral deletions" {
    try std.testing.expectEqual(.allow, decide("rm -rf dist && rm -rf build"));
}

test "allow env wrapped ephemeral rm" {
    try std.testing.expectEqual(.allow, decide("env rm -rf node_modules"));
}

// --- preserved deny: catastrophic / ambiguous ---

test "deny rm -rf root" {
    try std.testing.expectEqual(.deny, decide("rm -rf /"));
}

test "allow rm -rf /tmp subpath" {
    try std.testing.expectEqual(.allow, decide("rm -rf /tmp/foo"));
}

test "allow rm -rf nested /tmp path" {
    try std.testing.expectEqual(.allow, decide("rm -rf /tmp/build/cache"));
}

test "allow rm -rf /var/tmp subpath" {
    try std.testing.expectEqual(.allow, decide("rm -rf /var/tmp/scratch"));
}

test "deny rm -rf bare /tmp root" {
    try std.testing.expectEqual(.deny, decide("rm -rf /tmp"));
}

test "deny rm -rf temp traversal escape" {
    try std.testing.expectEqual(.deny, decide("rm -rf /tmp/../etc"));
}

test "deny rm -rf tmp-lookalike prefix" {
    try std.testing.expectEqual(.deny, decide("rm -rf /tmpfoo/x"));
}

test "deny rm -rf /tmp dot alias of root" {
    try std.testing.expectEqual(.deny, decide("rm -rf /tmp/."));
}

test "deny rm -rf /tmp multi-dot alias of root" {
    try std.testing.expectEqual(.deny, decide("rm -rf /tmp/./."));
}

test "allow rm -rf /tmp dot real subpath" {
    try std.testing.expectEqual(.allow, decide("rm -rf /tmp/./scratch"));
}

test "deny rm -rf home tilde" {
    try std.testing.expectEqual(.deny, decide("rm -rf ~"));
}

test "deny rm -rf tilde path" {
    try std.testing.expectEqual(.deny, decide("rm -rf ~/work"));
}

test "deny rm -rf HOME var" {
    try std.testing.expectEqual(.deny, decide("rm -rf $HOME"));
}

test "deny rm -rf variable target" {
    try std.testing.expectEqual(.deny, decide("rm -rf $DIR"));
}

test "deny rm -rf in-repo source dir" {
    try std.testing.expectEqual(.deny, decide("rm -rf src"));
}

test "deny rm -rf dot-git" {
    try std.testing.expectEqual(.deny, decide("rm -rf .git"));
}

test "deny rm -rf parent traversal" {
    try std.testing.expectEqual(.deny, decide("rm -rf ../sibling"));
}

test "deny rm -rf ephemeral with parent traversal" {
    try std.testing.expectEqual(.deny, decide("rm -rf node_modules/../src"));
}

test "deny rm -rf glob under ephemeral" {
    try std.testing.expectEqual(.deny, decide("rm -rf node_modules/*"));
}

test "deny rm -rf with one bad target among ephemeral" {
    try std.testing.expectEqual(.deny, decide("rm -rf node_modules /"));
}

test "deny chained ephemeral then catastrophic" {
    try std.testing.expectEqual(.deny, decide("rm -rf dist && rm -rf /"));
}

test "deny rm -rf no target" {
    try std.testing.expectEqual(.deny, decide("rm -rf"));
}

// --- regression guards: wrapper-obscured rm must stay deny ---

test "deny xargs rm -rf absolute" {
    try std.testing.expectEqual(.deny, decide("echo /etc | xargs rm -rf /"));
}

test "deny env wrapped catastrophic rm" {
    try std.testing.expectEqual(.deny, decide("env rm -rf /"));
}

test "deny sudo rm -rf even on ephemeral" {
    try std.testing.expectEqual(.deny, decide("sudo rm -rf node_modules"));
}

// --- false-positive guards ---

test "allow non-recursive rm of a file" {
    try std.testing.expectEqual(.allow, decide("rm file.txt"));
}

test "allow rm -f non-recursive" {
    try std.testing.expectEqual(.allow, decide("rm -f build.log"));
}

test "allow echo mentioning rm -rf" {
    try std.testing.expectEqual(.allow, decide("echo 'rm -rf /'"));
}

test "allow commit message mentioning rm -rf src" {
    try std.testing.expectEqual(.allow, decide("git commit -m \"chore: rm -rf src cleanup\""));
}

// --- review finding: recursive flag bundles where r/R is not first ---

test "deny rm -vr root" {
    try std.testing.expectEqual(.deny, decide("rm -vr /"));
}

test "deny rm -vrf root" {
    try std.testing.expectEqual(.deny, decide("rm -vrf /"));
}

test "deny rm -fvr root" {
    try std.testing.expectEqual(.deny, decide("rm -fvr /"));
}

test "deny rm -vr in-repo src" {
    try std.testing.expectEqual(.deny, decide("rm -vr src"));
}

test "allow rm -vr ephemeral" {
    try std.testing.expectEqual(.allow, decide("rm -vr node_modules"));
}

// --- review finding: ".." substring must not over-deny a filename ---

test "allow rm -rf ephemeral with dotdot in filename" {
    try std.testing.expectEqual(.allow, decide("rm -rf node_modules/foo..bar"));
}

test "deny rm -rf still catches real parent traversal" {
    try std.testing.expectEqual(.deny, decide("rm -rf node_modules/../etc"));
}

// --- end-of-options handling for non-recursive rm of dash-named file ---

test "allow non-recursive rm of dash-named file after end-of-options" {
    try std.testing.expectEqual(.allow, decide("rm -- -weirdfile"));
}
