<?php
/**
 * ------------------------------------------------
 * Encrypt PHP session data using files
 * ------------------------------------------------
 * The encryption is built using mcrypt extension 
 * and the randomness is managed by openssl
 * The default encryption algorithm is AES (Rijndael-128)
 * and we use CBC+HMAC (Encrypt-then-mac) with SHA-256
 * 
 * @author    Enrico Zimuel (enrico@zimuel.it)
 * @copyright GNU General Public License
 */
class SecureSession
{
    /**
     * Detailed error logging
     *
     * Setting this will log the entire lifecycle of every session to the configured error log.
     */
    const LOG                       = true;

    /**
     * Amount of time in seconds to subtract from time() in order to make sure cookie is expired
     * when we are trying to expire the cookie.d
     */
    const COOKIE_EXPIRATION_TIME    = 50000;

    /**
     * Encryption algorithm
     */
    const ALGORITHM_ENCRYPTION      = MCRYPT_RIJNDAEL_128;

    /**
     * Hash algorithm
     */
    const ALGORITHM_HASH            = 'sha256';

    /**
     * Key for encryption/decryption
    * 
    * @var string
    */
    protected $_key;

    /**
     * Key for HMAC authentication
    * 
    * @var string
    */
    protected $_auth;

    /**
     * Path of the session file
     *
     * @var string
     */
    protected $_path;

    /**
     * Session name (optional)
     * 
     * @var string
     */
    protected $_name;

    /**
     * Size of the IV vector for encryption
     * 
     * @var integer
     */
    protected $_ivSize;

    /**
     * Cookie variable name of the encryption + auth key
     * 
     * @var string
     */
    protected $_keyName;

    /**
     * Current cookie parameter settings
     *
     * @var array
     */
    protected $_cookieParams = array();

    /**
     * Session id passed during read(), to be compared with session id passed during write() to detect
     * session_regenerate_id call.
     *
     * @var string
     */
    protected $_sessionId   = '';

    /**
     * Generate a random key using openssl fallback to mcrypt_create_iv
     *
     * @param int $length
     * @return string
     * @throws Exception
     */
    protected function _randomKey($length=32)
    {
        if (function_exists('openssl_random_pseudo_bytes'))
        {
            $rnd = openssl_random_pseudo_bytes($length, $strong);
            if ($strong === true)
            {
                return $rnd;
            }    
        }
        if (defined('MCRYPT_DEV_URANDOM'))
        {
            return mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
        }
        else
        {
            throw new Exception('I cannot generate a secure pseudo-random key. Please install OpenSSL or Mcrypt extension');
        }	
    }

    /**
     * Constructor
     *
     * @access public
     * @throws Exception
     */
    public function __construct()
    {
        $this->_errorLog(__CLASS__ . ' :: __construct()');

        /**
         * Test if session is already active. If so we will not be able to guarantee the
         * secure session handler is being used to write the session data.
         */
        if($this->_isSessionActive())
        {
            throw new Exception('Session already created.');
        }
        else
        {
            // register shutdown
            register_shutdown_function('session_write_close');

            // set ini parameters for this session
            $this->_setSessionConfiguration();

            // set session handler
            session_set_save_handler(
                array($this, "open"),
                array($this, "close"),
                array($this, "read"),
                array($this, "write"),
                array($this, "destroy"),
                array($this, "gc")
            );

            // get cookie params
            $this->_cookieParams = session_get_cookie_params();
        }
    }

    /**
     * Set opinionated values about session configuration for secure sessions.
     *
     * @access private
     * @return void
     */
    private function _setSessionConfiguration()
    {
        ini_set('session.use_cookies',              1);
        ini_set('session.use_only_cookies',         1);
        ini_set('session.cookie_httponly',          1);
        ini_set('session.cookie_path',              '/');
        ini_set('session.cookie_lifetime',          1800);
        ini_set('session.cookie_domain',            $_SERVER['HTTP_HOST']);
        ini_set('session.hash_function',            self::ALGORITHM_HASH);
        ini_set('session.hash_bits_per_character',  5);
        ini_set('session.entropy_file',             '/dev/urandom');
        ini_set('session.entropy_length',           32);
    }

    /**
     * Has a session previously been started.
     *
     * @access private
     * @return bool
     */
    private function _isSessionActive()
    {
        if(version_compare(PHP_VERSION, '5.4', '<'))
        {
            // if PHP <= 5.3.x method
            if(defined('SID') && constant('SID') !== false && session_id())
            {
                return true;
            }
        }
        else
        {
            // PHP 5.4+ method
            if(PHP_SESSION_ACTIVE === session_status())
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Open the session
     * 
     * @param  string $save_path
     * @param  string $session_name
     * @return bool
     */
    public function open($save_path, $session_name) 
    {
        $this->_errorLog(__CLASS__ . ' :: open(' . $save_path . ', ' . $session_name . ')');

        $this->_path    = $save_path . DIRECTORY_SEPARATOR;
        $this->_name    = $session_name;
        $this->_keyName = "KEY_$session_name";
        $this->_ivSize  = mcrypt_get_iv_size(self::ALGORITHM_ENCRYPTION, MCRYPT_MODE_CBC);
        if (empty($_COOKIE[$this->_keyName]) || strpos($_COOKIE[$this->_keyName], ':') === false)
        {
            $keyLength    = mcrypt_get_key_size(self::ALGORITHM_ENCRYPTION, MCRYPT_MODE_CBC);
            $this->_key   = self::_randomKey($keyLength);
            $this->_auth  = self::_randomKey(32);
            $this->_setCookie(
                $this->_keyName,
                base64_encode($this->_key) . ':' . base64_encode($this->_auth)
            );
        }
        else
        {
            list ($this->_key, $this->_auth) = explode (':', $_COOKIE[$this->_keyName]);
            $this->_key  = base64_decode($this->_key);
            $this->_auth = base64_decode($this->_auth);
        }
        return true;
    }

    /**
     * Close the session
     * 
     * @return bool
     */
    public function close() 
    {
        $this->_errorLog(__CLASS__ . ' :: close()');
        return true;
    }

    /**
     * Read and decrypt the session
     * 
     * @param  integer $id
     * @return string 
     */
    public function read($id) 
    {
        $this->_errorLog(__CLASS__ . ' :: read(' . $id . ')');

        // remember initial session id
        $this->_sessionId = $id;

        $sess_file = $this->_path . $this->_name . "_$id";
        if (!file_exists($sess_file))
        {
            return false;
        }    
        $data      = file_get_contents($sess_file);
        list($hmac, $iv, $encrypted) = explode(':', $data);

        return $this->_decrypt($hmac, $iv, $encrypted);
    }

    /**
     * Encrypt and write the session
     * 
     * @param integer $id
     * @param string $data
     * @return bool
     */
    public function write($id, $data) 
    {
        $this->_errorLog(__CLASS__ . ' :: write(' . $id . ', ' . $data . ')');

        // Support session_regenerate_id() by detecting session id change, resend _keyName hmac cookie for new session id.
        if($this->_sessionId != $id)
        {
            // write key cookie so next read will not fail hmac test.
            $this->_setCookie(
                $this->_keyName,
                base64_encode($this->_key) . ':' . base64_encode($this->_auth)
            );
        }

        // encrypt the data, returns array with hmac, iv and encrypted data to be written
        $encrypted = $this->_encrypt($data);

        $sess_file = $this->_path . $this->_name . "_$id";
        $bytes = file_put_contents($sess_file, $encrypted['hmac'] . ':' . base64_encode($encrypted['iv']) . ':' . base64_encode($encrypted['encrypted_data']), LOCK_EX);
        return ($bytes !== false);  
    }

    /**
     * Destroy the session
     * 
     * @param int $id
     * @return bool
     */
    public function destroy($id) 
    {
        $this->_errorLog(__CLASS__ . ' :: destroy(' . $id . ')');

        $sess_file = $this->_path . $this->_name . "_$id";
        $this->_setCookie(
            $this->_keyName,
            '',
            true
        );
        $this->_setCookie(
            session_name(),
            '',
            true
        );
        return(@unlink($sess_file));
    }

    /**
     * Garbage Collector
     * 
     * @param int $max 
     * @return bool
     */
    public function gc($max) 
    {
        $this->_errorLog(__CLASS__ . ' :: gc(' . $max . ')');

        foreach (glob($this->_path . $this->_name . '_*') as $filename)
        {
            if (filemtime($filename) + $max < time())
            {
                @unlink($filename);
            }
        }
        return true;
    }

    /**
     * @param string $data
     * @return array
     */
    protected function _encrypt($data = '')
    {
        $iv        = mcrypt_create_iv($this->_ivSize, MCRYPT_DEV_URANDOM);
        $encrypted = mcrypt_encrypt(
            self::ALGORITHM_ENCRYPTION,
            $this->_key,
            $data,
            MCRYPT_MODE_CBC,
            $iv
        );
        $hmac  = hash_hmac(self::ALGORITHM_HASH, $iv . self::ALGORITHM_ENCRYPTION . $encrypted, $this->_auth);
        return array('hmac' => $hmac, 'iv' => $iv, 'encrypted_data' => $encrypted);
    }

    /**
     * @param string $hmac
     * @param string $iv
     * @param string $encrypted
     * @return bool|string
     */
    protected function _decrypt($hmac = '', $iv = '', $encrypted = '')
    {
        $iv        = base64_decode($iv);
        $encrypted = base64_decode($encrypted);
        $newHmac   = hash_hmac(self::ALGORITHM_HASH, $iv . self::ALGORITHM_ENCRYPTION . $encrypted, $this->_auth);
        if ($hmac !== $newHmac)
        {
            $this->_errorLog('HMAC test failure.');
            return false;
        }
        $decrypt = mcrypt_decrypt(
            self::ALGORITHM_ENCRYPTION,
            $this->_key,
            $encrypted,
            MCRYPT_MODE_CBC,
            $iv
        );
        return rtrim($decrypt, "\0");
    }

    /**
     * Setcookie wrapper
     *
     * @param string $name
     * @param string $value
     * @param bool $expire
     * @return bool
     */
    private function _setCookie($name = '', $value = '', $expire = false)
    {
        $cookieLifetime = ($expire)
            ? time() - self::COOKIE_EXPIRATION_TIME
            : time() + $this->_cookieParams['lifetime'];

        $isCookieSet = setcookie(
            $name,
            $value,
            $cookieLifetime,
            $this->_cookieParams['path'],
            $this->_cookieParams['domain'],
            $this->_cookieParams['secure'],
            $this->_cookieParams['httponly']
        );

        if(!$isCookieSet)
        {
            $this->_errorLog('Unable to set cookie: ' . $name . ' with value: ' . $value);
        }

        return $isCookieSet;
    }

    /**
     * @param string $message
     */
    private function _errorLog($message = '')
    {
        if(self::LOG)
        {
            error_log($message);
        }
    }
}
