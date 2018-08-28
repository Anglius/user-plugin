<?php namespace Crytofy\User\Updates;

use October\Rain\Database\Updates\Migration;
use DbDongle;

class UpdateTimestampsNullable extends Migration
{
    public function up()
    {
        DbDongle::disableStrictMode();

        DbDongle::convertTimestamps('users');
        DbDongle::convertTimestamps('user_groups');
        DbDongle::convertTimestamps('crytofy_user_mail_blockers');
    }

    public function down()
    {
        // ...
    }
}
