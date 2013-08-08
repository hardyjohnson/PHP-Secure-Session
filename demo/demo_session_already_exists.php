<?php
/**
 * Demo script for SecureSession
 *
 * Test to see if we throw exception if session has been started prior to us setting the save handler.
 * 
 * @author  Hardy Johnson
 * @license MIT
 */
require_once '../SecureSession.php';

session_start();

try
{
    $sessionHandler = new SecureSession();
}
catch (Exception $e)
{
    die('There has been an exception: ' . $e->getMessage());
}

session_start();
if(empty($_SESSION['original_starttime']))
{
    $_SESSION['original_starttime']     = time();
    $_SESSION['original_session_id']    = session_id();
}

var_dump(session_id(), $_SESSION);