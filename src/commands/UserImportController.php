<?php

namespace samkoch\yii2user\commands;

use Yii;
use yii\console\Controller;
use samkoch\yii2user\models\User;


/**
 * Imports AD users.
 *
 */
class UserImportController extends Controller
{
    const LOG_TARGET = 'import';

    public $importedObjectGuids = [];

    /**
     * Retrieve users from Active Directory
     *
     */
    public function actionIndex()
    {
        if (is_array(Yii::$app->params['userGroups'])) {
            foreach (Yii::$app->params['userGroups'] as $role => $adGroup) {
                $adUsers = $this->retrieveUsersFromDirectory($adGroup);

                if($adUsers && is_array($adUsers)) {
                    foreach ($adUsers as $adUser) {
                        $this->importUser($adUser, $adGroup, $role === 'admin' ? true : false);
                    }
                }
            }

            $this->cleanUpUsers();
        }
    }

    public function retrieveUsersFromDirectory($group)
    {
        $filter = '(&(objectClass=Group)(CN=' . $group . '))';
        $groupAttributes = ['objectGUID', 'displayName', 'distinguishedName', 'managedBy'];
        $userAttributes = ['objectGUID', 'displayName', 'distinguishedName', 'mail', 'sAMAccountName', 'sn', 'givenName'];
        $rangeAttributes = ['member'];
        $memberFilterGroups = [
            [
                'type' => 'AND',
                'value' => 'OU=Groups',
            ],
            [
                'type' => 'OR',
                'value' => [
                    'CN=ARG_',
                    'CN=ORG_',
                    'CN=PRO_',
                ],
            ],
        ];
        $memberFilterUser = [['value' => 'OU=Users']];

        Yii::info('Retrieving users from directory.', self::LOG_TARGET);

        //get LDAP component
        $ldap = yii::$app->ldap;

        return $ldap->getResolvedUsers($filter, $groupAttributes, $rangeAttributes, $userAttributes, $memberFilterGroups, $memberFilterUser);
    }

    public function importUser($adUser, $adGroup, $admin = false)
    {
        $adUser['displayName'] = utf8_encode($adUser['displayName']);

        $user = User::find()->where(['object_guid' => $adUser['objectGUID']])->one();
        if (!$user) {
            $user = new User;
            $user->object_guid = $adUser['objectGUID'];

            Yii::info('Added new user ' . $adUser['displayName'] . '.', self::LOG_TARGET);
        } else {
            Yii::info('Updated user ' . $adUser['displayName'] . '.', self::LOG_TARGET);
        }

        $user->email = $adUser['mail'];
        $user->display_name = $adUser['displayName'];
        $user->username = $adUser['sAMAccountName'];
        $user->first_name = $adUser['givenName'];
        $user->last_name = $adUser['sn'];
        $user->status = User::STATUS_ACTIVE;

        $user->user_group_id = User::USERGROUP_USER;
        if($admin === true) {
            $user->user_group_id = User::USERGROUP_ADMIN;
        }

        if (count($user->getMemberOfAdAsArray())) {
            $user->setMemberOfAdFromArray(array_merge($user->getMemberOfAdAsArray(), [$adGroup]));
        } else {
            $user->setMemberOfAdFromArray([$adGroup]);
        }

        $this->importedObjectGuids[] = $adUser['objectGUID'];

        return $user->save();
    }

    public function cleanUpUsers()
    {
        //delete not imported users, except admin and local users
        $usersToBeDeleted = User::find()
            ->where(['!=', 'user_group_id', User::USERGROUP_ADMIN])
            ->andWhere(['!=', 'local_user', 1])
            ->andWhere(['NOT IN', 'object_guid', $this->importedObjectGuids])
            ->andWhere(['!=', 'status', User::STATUS_DELETED])
            ->all();

        Yii::info('Deleted ' . count($usersToBeDeleted) . ' obsolete users.', self::LOG_TARGET);

        foreach ($usersToBeDeleted as $userToBeDeleted) {
            $userToBeDeleted->status = User::STATUS_DELETED;
            $userToBeDeleted->save(false);
        }
    }

}
