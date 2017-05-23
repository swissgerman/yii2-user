Yii2 user
=========

Yii2 user components

## Installation

It is recommended to use [composer](https://getcomposer.org) to install the library.

```bash
$ composer require samkoch/yii2-user
$ ./yii migrate/up --migrationPath=@vendor/samkoch/yii2-user/src/migrations
```
```bash
    'login' => [
        //default true
        //'enableSSO' => true,

        //default false
        'onTheFlyADImport' => true,

        //Is bound to onTheFlyADImport;
        // default empty, means all Groups are allowed
        'userGroups' => ['someAdminGroupName' => \samkoch\yii2user\models\User::USERGROUP_ADMIN],


    ],
```
