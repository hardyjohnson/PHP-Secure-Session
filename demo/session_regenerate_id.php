<?php
/**
 * Demo script for SecureSession
 *
 * Test regenerating session ID using session_regenerate_id
 *
 * session_id and $_SESSION['original_session_id'] should not match, subsequent re-loads should create a new session id
 * but $_SESSION['original_starttime'] and $_SESSION['original_session_id'] should stay the same as the first load.
 *
 *
 * @author  Hardy Johnson
 * @license MIT
 */
require_once '../SecureSession.php';

try
{
    $sessionHandler = new SecureSession();
}
catch (Exception $e)
{
    die('There has been an exception: ' . $e->getMessage());
}

session_start();
if(!isset($_SESSION['original_starttime']))
{
    $_SESSION['original_starttime']     = time();
    $_SESSION['original_session_id']    = session_id();
}

if(session_id() == $_SESSION['original_session_id'])
{
    session_regenerate_id(true);
    echo 'Regenerating ';
}

echo 'Reload this page to see session is stable after initial session regeneration.<br/>';
echo 'Current Session ID: ' . session_id() . '<br/>';
echo '$_SESSION: ';
var_dump($_SESSION);