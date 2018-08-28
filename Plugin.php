<?php namespace Cryptofy\User;

use App;
use Auth;
use Event;
use Backend;
use System\Classes\PluginBase;
use System\Classes\SettingsManager;
use Illuminate\Foundation\AliasLoader;
use Cryptofy\User\Classes\UserRedirector;
use Cryptofy\User\Models\MailBlocker;
use Cryptofy\Notify\Classes\Notifier;

class Plugin extends PluginBase
{
    /**
     * @var boolean Determine if this plugin should have elevated privileges.
     */
    public $elevated = true;

    public function pluginDetails()
    {
        return [
            'name'        => 'cryptofy.user::lang.plugin.name',
            'description' => 'cryptofy.user::lang.plugin.description',
            'author'      => 'Coinspace',
            'icon'        => 'icon-user',
            'homepage'    => 'https://github.com/Anglius/user-plugin'
        ];
    }

    public function register()
    {
        $alias = AliasLoader::getInstance();
        $alias->alias('Auth', 'Cryptofy\User\Facades\Auth');

        App::singleton('user.auth', function() {
            return \Cryptofy\User\Classes\AuthManager::instance();
        });

        App::singleton('redirect', function ($app) {
            // overrides with our own extended version of Redirector to support
            // seperate url.intended session variable for frontend
            $redirector = new UserRedirector($app['url']);

            // If the session is set on the application instance, we'll inject it into
            // the redirector instance. This allows the redirect responses to allow
            // for the quite convenient "with" methods that flash to the session.
            if (isset($app['session.store'])) {
                $redirector->setSession($app['session.store']);
            }

            return $redirector;
        });

        /*
         * Apply user-based mail blocking
         */
        Event::listen('mailer.prepareSend', function($mailer, $view, $message) {
            return MailBlocker::filterMessage($view, $message);
        });

        /*
         * Compatability with Cryptofy.Notify
         */
        $this->bindNotificationEvents();
    }

    public function registerComponents()
    {
        return [
            \Cryptofy\User\Components\Session::class       => 'session',
            \Cryptofy\User\Components\Account::class       => 'account',
            \Cryptofy\User\Components\ResetPassword::class => 'resetPassword'
        ];
    }

    public function registerPermissions()
    {
        return [
            'cryptofy.users.access_users' => [
                'tab'   => 'cryptofy.user::lang.plugin.tab',
                'label' => 'cryptofy.user::lang.plugin.access_users'
            ],
            'cryptofy.users.access_groups' => [
                'tab'   => 'cryptofy.user::lang.plugin.tab',
                'label' => 'cryptofy.user::lang.plugin.access_groups'
            ],
            'cryptofy.users.access_settings' => [
                'tab'   => 'cryptofy.user::lang.plugin.tab',
                'label' => 'cryptofy.user::lang.plugin.access_settings'
            ],
            'cryptofy.users.impersonate_user' => [
                'tab'   => 'cryptofy.user::lang.plugin.tab',
                'label' => 'cryptofy.user::lang.plugin.impersonate_user'
            ],
        ];
    }

    public function registerNavigation()
    {
        return [
            'user' => [
                'label'       => 'cryptofy.user::lang.users.menu_label',
                'url'         => Backend::url('cryptofy/user/users'),
                'icon'        => 'icon-user',
                'iconSvg'     => 'plugins/cryptofy/user/assets/images/user-icon.svg',
                'permissions' => ['cryptofy.users.*'],
                'order'       => 500,

                'sideMenu' => [
                    'users' => [
                        'label' => 'cryptofy.user::lang.users.menu_label',
                        'icon'        => 'icon-user',
                        'url'         => Backend::url('cryptofy/user/users'),
                        'permissions' => ['cryptofy.users.access_users']
                    ],
                    'usergroups' => [
                        'label'       => 'cryptofy.user::lang.groups.menu_label',
                        'icon'        => 'icon-users',
                        'url'         => Backend::url('cryptofy/user/usergroups'),
                        'permissions' => ['cryptofy.users.access_groups']
                    ]
                ]
            ]
        ];
    }

    public function registerSettings()
    {
        return [
            'settings' => [
                'label'       => 'cryptofy.user::lang.settings.menu_label',
                'description' => 'cryptofy.user::lang.settings.menu_description',
                'category'    => SettingsManager::CATEGORY_USERS,
                'icon'        => 'icon-cog',
                'class'       => 'Cryptofy\User\Models\Settings',
                'order'       => 500,
                'permissions' => ['cryptofy.users.access_settings']
            ]
        ];
    }

    public function registerMailTemplates()
    {
        return [
            'cryptofy.user::mail.activate',
            'cryptofy.user::mail.welcome',
            'cryptofy.user::mail.restore',
            'cryptofy.user::mail.new_user',
            'cryptofy.user::mail.reactivate',
            'cryptofy.user::mail.invite',
        ];
    }

    public function registerNotificationRules()
    {
        return [
            'groups' => [
                'user' => [
                    'label' => 'User',
                    'icon' => 'icon-user'
                ],
            ],
            'events' => [
                \Cryptofy\User\NotifyRules\UserActivatedEvent::class,
                \Cryptofy\User\NotifyRules\UserRegisteredEvent::class,
            ],
            'actions' => [],
            'conditions' => [
                \Cryptofy\User\NotifyRules\UserAttributeCondition::class
            ],
        ];
    }

    protected function bindNotificationEvents()
    {
        if (!class_exists(Notifier::class)) {
            return;
        }

        Notifier::bindEvents([
            'cryptofy.user.activate' => \Cryptofy\User\NotifyRules\UserActivatedEvent::class,
            'cryptofy.user.register' => \Cryptofy\User\NotifyRules\UserRegisteredEvent::class
        ]);

        Notifier::instance()->registerCallback(function($manager) {
            $manager->registerGlobalParams([
                'user' => Auth::getUser()
            ]);
        });
    }
}
