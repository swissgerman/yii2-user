<?php

use yii\db\Migration;

class m170509_213136_user extends Migration
{
    protected $tableOptions = 'CHARACTER SET utf8 COLLATE utf8_unicode_ci ENGINE=InnoDB';

    public function up()
    {
        $this->createTable('{{%user}}', [
            'id' => $this->primaryKey(),
            'object_guid' => $this->string(255)->null(),
            'username' => $this->string(255)->null(),
            'user_group_id' => $this->integer()->notNull(),
            'auth_key' => $this->string(32)->null(),
            'password_hash' => $this->string(255)->null(),
            'password_reset_token' => $this->string(255)->null(),
            'first_name' => $this->string(255)->null(),
            'last_name' => $this->string(255)->null(),
            'email' => $this->string(255)->notNull(),
            'status' => $this->integer()->notNull(),
            'local_user' => $this->integer()->notNull(),
            'member_of_ad' => $this->string(255)->null(),
            'last_login' => $this->integer()->null(),
            'ip' => $this->string(255)->null(),
            'display_name' => $this->string(255)->null(),
            'created_at' => $this->integer()->notNull(),
            'updated_at' => $this->integer()->notNull(),
        ], $this->tableOptions);

        $this->createIndex('{{%user_unique_username}}', '{{%user}}', 'username', true);
        $this->createIndex('{{%user_unique_email}}', '{{%user}}', 'email', true);
    }

    public function down()
    {
        $this->dropTable('{{%user}}');
    }

}
