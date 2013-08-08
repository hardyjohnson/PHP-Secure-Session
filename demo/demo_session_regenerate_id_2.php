<?php
/**
 * Second page
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

session_regenerate_id(true);
