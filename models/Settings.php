<?php namespace Crytofy\User\Models;

use Lang;
use Model;
use Crytofy\User\Models\User as UserModel;

class Settings extends Model
{
    /**
     * @var array Behaviors implemented by this model.
     */
    public $implement = [
        \System\Behaviors\SettingsModel::class
    ];

    public $settingsCode = 'user_settings';
    public $settingsFields = 'fields.yaml';

    const ACTIVATE_AUTO = 'auto';
    const ACTIVATE_USER = 'user';
    const ACTIVATE_ADMIN = 'admin';

    const LOGIN_EMAIL = 'email';
    const LOGIN_USERNAME = 'username';
    const LOGIN_BOTH = 'both';

    public function initSettingsData()
    {
        $this->require_activation = true;
        $this->activate_mode = self::ACTIVATE_AUTO;
        $this->use_throttle = true;
        $this->block_persistence = false;
        $this->allow_registration = true;
        $this->login_attribute = self::LOGIN_EMAIL;
    }

    public function getActivateModeOptions()
    {
        return [
            self::ACTIVATE_AUTO => [
                'crytofy.user::lang.settings.activate_mode_auto',
                'crytofy.user::lang.settings.activate_mode_auto_comment'
            ],
            self::ACTIVATE_USER => [
                'crytofy.user::lang.settings.activate_mode_user',
                'crytofy.user::lang.settings.activate_mode_user_comment'
            ],
            self::ACTIVATE_ADMIN => [
                'crytofy.user::lang.settings.activate_mode_admin',
                'crytofy.user::lang.settings.activate_mode_admin_comment'
            ]
        ];
}

    public function getLoginAttributeOptions()
    {
        return [
            self::LOGIN_EMAIL => ['crytofy.user::lang.login.attribute_email'],
            self::LOGIN_USERNAME => ['crytofy.user::lang.login.attribute_username'],
            self::LOGIN_BOTH => ['Username and email']
        ];
    }

    public function getActivateModeAttribute($value)
    {
        if (!$value) {
            return self::ACTIVATE_AUTO;
        }

        return $value;
    }
}
