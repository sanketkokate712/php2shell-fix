<?php
/**
 * PHP2Shell checker (CVE-2026-109618, CVE-2026-109619)
 *
 * Reports whether the PHP running this script is patched, and the current
 * values of the temporary mitigation settings. Read-only: changes nothing.
 *
 * Web:  copy into a web root under a random name, request it, DELETE IT.
 * CLI:  php check.php                   (checks this php binary)
 *       php check.php --verdict=8.3.20  (verdict for a version string only)
 *
 * Written for PHP 5.4+ syntax on purpose: old servers are the ones at risk.
 */

// Only these addresses may view the web report. Add your own IP if you must
// open it from a browser, and delete the file as soon as you are done.
$ALLOWED_IPS = array('127.0.0.1', '::1');

/** First patched release of every branch that received official fixes. */
function php2shell_fixed_versions()
{
    return array(
        '8.5' => '8.5.12',
        '8.4' => '8.4.27',
        '8.3' => '8.3.36',
        '8.2' => '8.2.35',
    );
}

/** Branches that only got source backports from the PHP team. */
function php2shell_eol_branches()
{
    return array('7.4', '8.0', '8.1');
}

/**
 * Split "8.1.2-1ubuntu2.22" into base "8.1.2", branch "8.1",
 * extra "-1ubuntu2.22". Distro builds put their package revision in extra.
 */
function php2shell_parse($version)
{
    if (!preg_match('/^(\d+)\.(\d+)\.(\d+)(.*)$/', trim($version), $m)) {
        return null;
    }
    return array(
        'base'   => $m[1] . '.' . $m[2] . '.' . $m[3],
        'branch' => $m[1] . '.' . $m[2],
        'extra'  => $m[4],
    );
}

/**
 * Returns one of: PATCHED, VULNERABLE, EOL, UNSUPPORTED, CHECK_VENDOR, UNKNOWN
 * (meanings are in SKILL.md, step 4).
 */
function php2shell_verdict($version)
{
    $v = php2shell_parse($version);
    if ($v === null) {
        return 'UNKNOWN';
    }
    $fixed = php2shell_fixed_versions();
    $eol   = php2shell_eol_branches();

    // A distro suffix means the fix may be backported without a version bump,
    // so an old-looking distro build is "check the changelog", not "vulnerable".
    $distro = $v['extra'] !== '' && $v['extra'] !== '-dev';

    if (isset($fixed[$v['branch']])) {
        if (version_compare($v['base'], $fixed[$v['branch']], '>=')) {
            return 'PATCHED';
        }
        return $distro ? 'CHECK_VENDOR' : 'VULNERABLE';
    }
    // Branches newer than every fixed one (8.6, 9.x) were released after the fix.
    if (version_compare($v['branch'], '8.5', '>')) {
        return 'PATCHED';
    }
    if ($distro) {
        return 'CHECK_VENDOR';
    }
    return in_array($v['branch'], $eol, true) ? 'EOL' : 'UNSUPPORTED';
}

/** "128M" -> 134217728. Returns -1 for "-1" (no limit). */
function php2shell_bytes($value)
{
    $value = trim((string) $value);
    if ($value === '-1') {
        return -1;
    }
    $num  = (int) $value;
    $unit = strtolower(substr($value, -1));
    if ($unit === 'g') {
        $num *= 1024 * 1024 * 1024;
    } elseif ($unit === 'm') {
        $num *= 1024 * 1024;
    } elseif ($unit === 'k') {
        $num *= 1024;
    }
    return $num;
}

function php2shell_is_on($value)
{
    $value = strtolower(trim((string) $value));
    return $value === '1' || $value === 'on' || $value === 'true' || $value === 'yes';
}

/** Each row: setting, current value, recommended value, OK?. */
function php2shell_mitigation_rows()
{
    $rows = array();

    $mem = ini_get('memory_limit');
    $rows[] = array('memory_limit', $mem, '-1', php2shell_bytes($mem) === -1);

    $post   = ini_get('post_max_size');
    $upload = ini_get('upload_max_filesize');
    $postB  = php2shell_bytes($post);
    $rows[] = array('post_max_size', $post, '8M (32M if uploads needed)',
        $postB > 0 && $postB <= 32 * 1024 * 1024);
    $rows[] = array('upload_max_filesize', $upload, 'below post_max_size',
        php2shell_bytes($upload) < $postB);

    $prog = ini_get('session.upload_progress.enabled');
    $rows[] = array('session.upload_progress.enabled', $prog === '' ? 'Off' : $prog,
        'Off', !php2shell_is_on($prog));

    if (version_compare(PHP_VERSION, '8.5.0', '>=')) {
        $bt = ini_get('fatal_error_backtraces');
        $rows[] = array('fatal_error_backtraces', $bt === '' ? 'Off' : $bt,
            'Off', !php2shell_is_on($bt));
    }
    return $rows;
}

function php2shell_report()
{
    $verdict = php2shell_verdict(PHP_VERSION);
    $out   = array();
    $out[] = 'PHP2Shell check (CVE-2026-109618, CVE-2026-109619)';
    $out[] = str_repeat('=', 52);
    $out[] = 'PHP version : ' . PHP_VERSION;
    $out[] = 'SAPI        : ' . PHP_SAPI;
    $out[] = 'Binary      : ' . (defined('PHP_BINARY') ? PHP_BINARY : 'n/a');
    $out[] = 'php.ini     : ' . (php_ini_loaded_file() ? php_ini_loaded_file() : 'none');
    $out[] = 'VERDICT     : ' . $verdict;
    $out[] = '';
    $out[] = 'Mitigation settings (only matter while unpatched):';
    foreach (php2shell_mitigation_rows() as $row) {
        $out[] = sprintf('  [%s] %-33s now: %-8s want: %s',
            $row[3] ? 'ok' : '!!', $row[0], $row[1], $row[2]);
    }
    if (PHP_SAPI !== 'cli') {
        $out[] = '';
        $out[] = 'DELETE THIS FILE NOW: ' . __FILE__;
    }
    return implode("\n", $out) . "\n";
}

// Tests define this to load the functions above without running the report.
if (defined('PHP2SHELL_LIBRARY_ONLY')) {
    return;
}

if (PHP_SAPI === 'cli') {
    $args = isset($argv) ? array_slice($argv, 1) : array();
    foreach ($args as $arg) {
        if (strpos($arg, '--verdict=') === 0) {
            echo php2shell_verdict(substr($arg, 10)) . "\n";
            exit(0);
        }
    }
    echo php2shell_report();
    exit(0);
}

$remote = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
if (!in_array($remote, $ALLOWED_IPS, true)) {
    header('HTTP/1.1 404 Not Found');
    exit;
}
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');
echo php2shell_report();
