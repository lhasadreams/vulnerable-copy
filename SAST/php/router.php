<?php

$ROLE_ACCESS = ["auditor" => true, "support" => true, "guest" => false];
$PROFILES_ROOT = "/srv/legacy/profiles/";

function body(): array
{
    $j = json_decode(file_get_contents("php://input"), true);
    return is_array($j) ? $j : [];
}
function send($x)
{
    header("Content-Type: application/json");
    echo json_encode($x);
}

$path = parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH);
$file = __DIR__ . $path;
if ($path !== "/" && file_exists($file) && !is_dir($file)) {
    return false;
}

$method = $_SERVER["REQUEST_METHOD"];

if ($path === "/legacy/login" && $method === "POST") {
    $b = body();
    $role = (string)($b["role"] ?? "guest");
    $pin = (string)($b["pin"] ?? "");
    $sec = @parse_ini_file("/srv/legacy/security.ini") ?: [];
    $expectedPin = (string)($sec["legacy_pin"] ?? "");
    $pinValid = $expectedPin !== "" && hash_equals($expectedPin, $pin);
    $ok = $pinValid && in_array($role, $GLOBALS["ROLE_ACCESS"]);
    send(["admin" => $ok, "granted_role" => $ok ? $role : "guest"]);
    return true;
}

if ($path === "/legacy/session/restore" && $method === "POST") {
    $b = body();
    $raw = base64_decode($b["state"] ?? "", true);
    $snap = json_decode($raw ?: "{}", true);
    $profile = str_replace("../", "", (string)($snap["profile"] ?? "default.ini"));
    $target = $GLOBALS["PROFILES_ROOT"] . $profile;
    $parsed = @parse_ini_file($target, false, INI_SCANNER_RAW);
    send(["restored" => is_array($parsed) ? $parsed : ["profile" => $profile]]);
    return true;
}

http_response_code(404);
send(["error" => "not found"]);
