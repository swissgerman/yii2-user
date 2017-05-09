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

    /**
     * Retrieve users from Active Directory
     *
     */
    public function actionIndex()
    {
        if (is_array(Yii::$app->params['userGroups']) && count(Yii::$app->params['userGroups'])) {
            $importedObjectGuids = [];

            foreach (Yii::$app->params['userGroups'] as $adGroup) {
                $filter = '(&(objectClass=Group)(CN=' . $adGroup . '))';
                $groupAttributes = array('objectGUID', 'displayName', 'distinguishedName', 'managedBy');
                $userAttributes = array('objectGUID', 'displayName', 'distinguishedName', 'mail', 'sAMAccountName', 'sn', 'givenName');
                $rangeAttributes = array('member');
                $memberFilterGroups = array(
                    array(
                        'type' => 'AND',
                        'value' => 'OU=Groups',
                    ),
                    array(
                        'type' => 'OR',
                        'value' => array(
                            'CN=ARG_',
                            'CN=ORG_',
                            'CN=PRO_',
                        ),
                    ),
                );
                $memberFilterUser = array(
                    array(
                        'value' => 'OU=Users',
                    ),
                );

                Yii::info('Retrieving users from Active Directory.', self::LOG_TARGET);

                //get LDAP component
                $ldap = yii::$app->ldap;

                $adUsers = $ldap->getResolvedUsers($filter, $groupAttributes,
                    $rangeAttributes, $userAttributes, $memberFilterGroups, $memberFilterUser);

                if ($adUsers && count($adUsers)) {
                    foreach ($adUsers as $adUser) {

                        $adUser['displayName'] = utf8_encode($adUser['displayName']);

                        $user = User::find()->where(['object_guid' => $adUser['objectGUID']])->one();
                        if (!$user) {
                            $user = new User;
                            $user->object_guid = $adUser['objectGUID'];

                            Yii::info('Adding new user ' . $adUser['displayName'] . '.', self::LOG_TARGET);
                        } else {
                            Yii::info('Updating user ' . $adUser['displayName'] . '.', self::LOG_TARGET);
                        }

                        $user->email = $adUser['mail'];
                        $user->display_name = $adUser['displayName'];
                        $user->username = $adUser['sAMAccountName'];
                        $user->first_name = $adUser['givenName'];
                        $user->last_name = $adUser['sn'];
                        $user->status = User::STATUS_ACTIVE;

                        if (count($user->getMemberOfAdAsArray())) {
                            $user->setMemberOfAdFromArray(array_merge($user->getMemberOfAdAsArray(), [$adGroup]));
                        } else {
                            $user->setMemberOfAdFromArray([$adGroup]);
                        }

                        $user->save();

                        $importedObjectGuids[] = $adUser['objectGUID'];
                    }
                }

            }

            //delete not imported users, except admin and local users
            $usersToBeDeleted = User::find()
                ->where(['!=', 'user_group_id', User::USERGROUP_ADMIN])
                ->andWhere(['!=', 'local_user', 1])
                ->andWhere(['NOT IN', 'object_guid', $importedObjectGuids])
                ->andWhere(['!=', 'status', User::STATUS_DELETED])
                ->all();

            Yii::info('Deleted ' . count($usersToBeDeleted) . ' obsolete users.', self::LOG_TARGET);

            foreach ($usersToBeDeleted as $userToBeDeleted) {
                $userToBeDeleted->status = User::STATUS_DELETED;
                $userToBeDeleted->save(false);
            }

        }

    }

}
