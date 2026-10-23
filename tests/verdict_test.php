<?php
// Tests for check.php. Run: php tests/verdict_test.php
// PHP 5.4+ syntax, so CI can run it on every PHP version the checker supports.

define('PHP2SHELL_LIBRARY_ONLY', true);
require dirname(__FILE__) . '/../skills/php2shell-fix/scripts/check.php';

$failures = 0;

function expect($label, $actual, $expected)
{
    global $failures;
    if ($actual === $expected) {
        echo "ok    $label\n";
    } else {
        echo "FAIL  $label: expected " . var_export($expected, true)
            . ', got ' . var_export($actual, true) . "\n";
        $failures++;
    }
}

$verdicts = array(
    // Exactly the fixed releases, and one below each
    '8.5.12' => 'PATCHED',
    '8.5.11' => 'VULNERABLE',
    '8.4.27' => 'PATCHED',
    '8.4.26' => 'VULNERABLE',
    '8.3.36' => 'PATCHED',
    '8.3.35' => 'VULNERABLE',
    '8.2.35' => 'PATCHED',
    '8.2.34' => 'VULNERABLE',
    '8.3.40' => 'PATCHED',
    '8.2.0'  => 'VULNERABLE',
    // Newer branches than any fixed one
    '8.6.0'  => 'PATCHED',
    '9.0.1'  => 'PATCHED',
    // End of life / unsupported
    '8.1.31' => 'EOL',
    '8.0.30' => 'EOL',
    '7.4.33' => 'EOL',
    '7.3.33' => 'UNSUPPORTED',
    '5.6.40' => 'UNSUPPORTED',
    '5.4.45' => 'UNSUPPORTED',
    // Distro builds (Ubuntu, Debian, sury.org)
    '8.3.6-1ubuntu0.24.04.5'                => 'CHECK_VENDOR',
    '8.1.2-1ubuntu2.22'                     => 'CHECK_VENDOR',
    '7.4.33-1+deb11u7'                      => 'CHECK_VENDOR',
    '8.3.36-1+ubuntu24.04.1+deb.sury.org+1' => 'PATCHED',
    // Development builds are not distro builds
    '8.5.12-dev' => 'PATCHED',
    '8.4.20-dev' => 'VULNERABLE',
    // Garbage
    ''        => 'UNKNOWN',
    'foo'     => 'UNKNOWN',
    '8.3'     => 'UNKNOWN',
);
foreach ($verdicts as $version => $want) {
    expect("verdict('$version')", php2shell_verdict($version), $want);
}

$bytes = array(
    '-1'   => -1,
    '8M'   => 8 * 1024 * 1024,
    '32M'  => 32 * 1024 * 1024,
    '512K' => 512 * 1024,
    '1G'   => 1024 * 1024 * 1024,
    '1000' => 1000,
);
foreach ($bytes as $in => $want) {
    expect("bytes('$in')", php2shell_bytes($in), $want);
}

expect("is_on('On')", php2shell_is_on('On'), true);
expect("is_on('1')", php2shell_is_on('1'), true);
expect("is_on('')", php2shell_is_on(''), false);
expect("is_on('0')", php2shell_is_on('0'), false);

// The report must run on this PHP without errors and include a verdict line.
$report = php2shell_report();
expect('report has verdict line', strpos($report, 'VERDICT     : ') !== false, true);

echo $failures === 0 ? "\nAll tests passed.\n" : "\n$failures test(s) failed.\n";
exit($failures === 0 ? 0 : 1);
