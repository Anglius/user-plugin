<?php namespace Crytofy\User\Classes;

use October\Rain\Auth\Manager as RainAuthManager;
use Crytofy\User\Models\Settings as UserSettings;
use Crytofy\User\Models\UserGroup as UserGroupModel;
use Crytofy\User\Models\User;
use October\Rain\Auth\AuthException;

class AuthManager extends RainAuthManager
{
    protected static $instance;

    protected $sessionKey = 'user_auth';

    protected $userModel = 'Crytofy\User\Models\User';

    protected $groupModel = 'Crytofy\User\Models\UserGroup';

    protected $throttleModel = 'Crytofy\User\Models\Throttle';

    public function init()
    {
        $this->useThrottle = UserSettings::get('use_throttle', $this->useThrottle);
        $this->requireActivation = UserSettings::get('require_activation', $this->requireActivation);
        parent::init();
    }

    /**
     * {@inheritDoc}
     */
    public function extendUserQuery($query)
    {
        $query->withTrashed();
    }

    /**
     * {@inheritDoc}
     */
    public function register(array $credentials, $activate = false, $autoLogin = true)
    {
        if ($guest = $this->findGuestUserByCredentials($credentials)) {
            return $this->convertGuestToUser($guest, $credentials, $activate);
        }

        return parent::register($credentials, $activate, $autoLogin);
    }

    //
    // Guest users
    //

    public function findGuestUserByCredentials(array $credentials)
    {
        if ($email = array_get($credentials, 'email')) {
            return $this->findGuestUser($email);
        }

        return null;
    }

    public function findGuestUser($email)
    {
        $query = $this->createUserModelQuery();

        return $user = $query
            ->where('email', $email)
            ->where('is_guest', 1)
            ->first();
    }

    /**
     * Registers a guest user by giving the required credentials.
     *
     * @param array $credentials
     * @return Models\User
     */
    public function registerGuest(array $credentials)
    {
        $user = $this->findGuestUserByCredentials($credentials);
        $newUser = false;

        if (!$user) {
            $user = $this->createUserModel();
            $newUser = true;
        }

        $user->fill($credentials);
        $user->is_guest = true;
        $user->save();

        // Add user to guest group
        if ($newUser && $group = UserGroupModel::getGuestGroup()) {
            $user->groups()->add($group);
        }

        // Prevents revalidation of the password field
        // on subsequent saves to this model object
        $user->password = null;

        return $this->user = $user;
    }

    /**
     * Converts a guest user to a registered user.
     *
     * @param Models\User $user
     * @param array $credentials
     * @param bool $activate
     * @return Models\User
     */
    public function convertGuestToUser($user, $credentials, $activate = false)
    {
        $user->fill($credentials);
        $user->convertToRegistered(false);

        // Remove user from guest group
        if ($group = UserGroupModel::getGuestGroup()) {
            $user->groups()->remove($group);
        }

        if ($activate) {
            $user->attemptActivation($user->getActivationCode());
        }

        // Prevents revalidation of the password field
        // on subsequent saves to this model object
        $user->password = null;

        return $this->user = $user;
    }

    /**
     * Finds a user by the login value.
     *
     * @param string $login
     * @return mixed (User || null)
     */
    public function findUserByLogin($login)
    {
        $model = $this->createUserModel();
        $query = $this->createUserModelQuery();
        $loginName = $model->getLoginName();
        if ($loginName === UserSettings::LOGIN_BOTH) {
            $user = $query->where(UserSettings::LOGIN_EMAIL, $login)->first();
            if (is_null($user)) {
                $query = $this->createUserModelQuery();
                $user = $query->where(UserSettings::LOGIN_USERNAME, $login)->first();
            }
        } else {
            $user = $query->where($model->getLoginName(), $login)->first();
        }
        return $user ?: null;
    }

    public function findUserByCredentials(array $credentials) {
        $model = $this->createUserModel();
        $loginName = $model->getLoginName();

        if (!array_key_exists($loginName, $credentials) && !array_key_exists('both', $credentials)) {
            throw new AuthException(sprintf('Login attribute "%s" was not provided.', $loginName));
        }
        $query = $this->createUserModelQuery();
        $hashableAttributes = $model->getHashableAttributes();
        $hashedCredentials = [];

        /*
         * Build query from given credentials
         */

        if (array_key_exists(UserSettings::LOGIN_BOTH, $credentials)) {
            foreach ($credentials as $credential => $value) {
                // All excepted the hashed attributes
                if (in_array($credential, $hashableAttributes)) {
                    $hashedCredentials = array_merge($hashedCredentials, [$credential => $value]);
                }
                else {
                    if ($credential === UserSettings::LOGIN_BOTH) {
                        $query->where(UserSettings::LOGIN_EMAIL, '=', $value)
                            ->orWhere(UserSettings::LOGIN_USERNAME, '=', $value);
                    } else {
                        $query = $query->where($credential, '=', $value);
                    }
                }
            }
        } else {
            foreach ($credentials as $credential => $value) {
                // All excepted the hashed attributes
                if (in_array($credential, $hashableAttributes)) {
                    $hashedCredentials = array_merge($hashedCredentials, [$credential => $value]);
                }
                else {
                    $query = $query->where($credential, '=', $value);
                }
            }
        }

        if (!$user = $query->first()) {
            throw new AuthException('A user was not found with the given credentials.');
        }

        /*
         * Check the hashed credentials match
         */
        foreach ($hashedCredentials as $credential => $value) {

            if (!$user->checkHashValue($credential, $value)) {
                // Incorrect password
                if ($credential == 'password') {
                    throw new AuthException(sprintf(
                        'A user was found to match all plain text credentials however hashed credential "%s" did not match.', $credential
                    ));
                }

                // User not found
                throw new AuthException('A user was not found with the given credentials.');
            }
        }

        return $user;
    }

    /**
     * Attempts to authenticate the given user according to the passed credentials.
     *
     * @param array $credentials The user login details
     * @param bool $remember Store a non-expire cookie for the user
     * @throws AuthException If authentication fails
     * @return User The successfully logged in user
     */
    public function authenticate(array $credentials, $remember = true)
    {
        /*
         * Default to the login name field or fallback to a hard-coded 'login' value
         */
        $loginName = $this->createUserModel()->getLoginName();
        $loginCredentialKey = (isset($credentials[$loginName])) ? $loginName : 'login';

        if (empty($credentials[$loginCredentialKey])) {
            throw new AuthException(sprintf('The "%s" attribute is required.', $loginCredentialKey));
        }

        if (empty($credentials['password'])) {
            throw new AuthException('The password attribute is required.');
        }

        /*
         * If the fallback 'login' was provided and did not match the necessary
         * login name, swap it over
         */
        if ($loginCredentialKey !== $loginName) {
            $credentials[$loginName] = $credentials[$loginCredentialKey];
            unset($credentials[$loginCredentialKey]);
        }

        /*
         * If throttling is enabled, check they are not locked out first and foremost.
         */
        if ($this->useThrottle) {
            $throttle = $this->findThrottleByLogin($credentials[$loginName], $this->ipAddress);
            $throttle->check();
        }

        /*
         * Look up the user by authentication credentials.
         */
        try {
            $user = $this->findUserByCredentials($credentials);
        }
        catch (AuthException $ex) {
            if ($this->useThrottle) {
                $throttle->addLoginAttempt();
            }

            throw $ex;
        }

        if ($this->useThrottle) {
            $throttle->clearLoginAttempts();
        }

        $user->clearResetPassword();
        $this->login($user, $remember);

        return $this->user;
    }
}
