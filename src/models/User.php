<?php

namespace samkoch\yii2user\models;

use Yii;
use yii\base\NotSupportedException;
use yii\behaviors\TimestampBehavior;
use yii\db\ActiveRecord;
use yii\web\IdentityInterface;
use yii\helpers\ArrayHelper;

/**
 * User model
 *
 * @property integer $id
 * @property string $object_guid
 * @property string $username
 * @property string $user_group_id
 * @property string $member_of_ad
 * @property string $auth_key
 * @property string $password_hash
 * @property string $password_reset_token
 * @property string $first_name
 * @property string $last_name
 * @property string $email
 * @property integer $status
 * @property integer $created_at
 * @property integer $updated_at
 * @property integer $last_login
 * @property string $ip
 * @property string $display_name
 * @property string $password write-only password
 */
class User extends ActiveRecord implements IdentityInterface
{
    const STATUS_DELETED = 0;
    const STATUS_ACTIVE = 10;

    const USERGROUP_ADMIN = 10;
    const USERGROUP_USER = 20;

    /**
     * @inheritdoc
     */
    public static function tableName()
    {
        return '{{%user}}';
    }

    /**
     * @inheritdoc
     */
    public function behaviors()
    {
        return [
            TimestampBehavior::className(),
        ];
    }

    /**
     * @inheritdoc
     */
    public function rules()
    {
        return [
            ['status', 'default', 'value' => self::STATUS_ACTIVE],
            ['status', 'in', 'range' => [self::STATUS_ACTIVE, self::STATUS_DELETED]],
        ];
    }

    /**
     * @inheritdoc
     */
    public static function findIdentity($id)
    {
        return static::findOne(['id' => $id, 'status' => self::STATUS_ACTIVE]);
    }

    /**
     * @inheritdoc
     */
    public static function findIdentityByAccessToken($token, $type = null)
    {
        throw new NotSupportedException('"findIdentityByAccessToken" is not implemented.');
    }

    /**
     * Finds user by username
     *
     * @param string $username
     * @return static|null
     */
    public static function findByUsername($username)
    {
        //get LDAP component
        $ldap = yii::$app->ldap;

        //if username is an email address, try to fetch sAMAccountName from active directory
        if (filter_var($username, FILTER_VALIDATE_EMAIL)) {
            return static::findOne(['email' => $username]);
        }

        return static::findOne(['username' => $username]);
    }

    /**
     * Finds user by password reset token
     *
     * @param string $token password reset token
     * @return static|null
     */
    public static function findByPasswordResetToken($token)
    {
        if (!static::isPasswordResetTokenValid($token)) {
            return null;
        }

        return static::findOne([
            'password_reset_token' => $token,
            'status' => self::STATUS_ACTIVE,
        ]);
    }

    /**
     * Finds out if password reset token is valid
     *
     * @param string $token password reset token
     * @return boolean
     */
    public static function isPasswordResetTokenValid($token)
    {
        if (empty($token)) {
            return false;
        }
        $expire = Yii::$app->params['user.passwordResetTokenExpire'];
        $parts = explode('_', $token);
        $timestamp = (int)end($parts);
        return $timestamp + $expire >= time();
    }

    /**
     * @inheritdoc
     */
    public function getId()
    {
        return $this->getPrimaryKey();
    }

    /**
     * @inheritdoc
     */
    public function getAuthKey()
    {
        return $this->auth_key;
    }

    /**
     * @inheritdoc
     */
    public function validateAuthKey($authKey)
    {
        return $this->getAuthKey() === $authKey;
    }

    /**
     * Validates password
     *
     * @param string $password password to validate
     * @return boolean if password provided is valid for current user
     */
    public function validatePassword($password)
    {
        $result = false;
        if($this->status == self::STATUS_DELETED){
            return $result;
        }

        //try db user login
        if ($this->password_hash) {
            $result = Yii::$app->security->validatePassword($password, $this->password_hash);
        }

        //try SSO login
        if (Yii::$app->session['authSsoLogin'] === true) {
            Yii::$app->session['authSsoLogin'] = false;
            return true;
        }

        //try ActiveDirectory login
        //get LDAP component
        $ldap = yii::$app->ldap;

        if ($ldap->validateUserCredentials($ldap->config['domain'] . '\\' . $this->username, $password)) {
            return true;
        }

        return $result;
    }

    /**
     * Generates password hash from password and sets it to the model
     *
     * @param string $password
     */
    public function setPassword($password)
    {
        $this->password_hash = Yii::$app->security->generatePasswordHash($password);
    }

    /**
     * Generates "remember me" authentication key
     */
    public function generateAuthKey()
    {
        $this->auth_key = Yii::$app->security->generateRandomString();
    }

    /**
     * Generates new password reset token
     */
    public function generatePasswordResetToken()
    {
        $this->password_reset_token = Yii::$app->security->generateRandomString() . '_' . time();
    }

    /**
     * Removes password reset token
     */
    public function removePasswordResetToken()
    {
        $this->password_reset_token = null;
    }

    /**
     * Creates user from directory using sAMAccountName or email.
     *
     * @param $username
     * @return \app\models\User
     * @throws \yii\base\Exception
     */
    public static function createUserFromDirectory($username)
    {
        $user = self::findByUsername($username);

        if (!$user) {

            //get LDAP component
            $ldap = yii::$app->ldap;

            //has groups to validate
            if(!empty(Yii::$app->params['login']['userGroups'])){
                $groups = '(|';
                foreach (Yii::$app->params['login']['userGroups'] as $group => $role){
                    $groups .= "(memberOf=CN=$group,OU=Distribution,OU=Groups,OU=M-Workplace,DC=corp,DC=ADS,DC=Migros,DC=ch)";
                }
                $groups .= ")";
            }

            //if email address was provided
            if (filter_var($username, FILTER_VALIDATE_EMAIL)) {
                $ldapData = $ldap->getEntries('(&(objectClass=User)(mail=' . $username . ')'.$groups.')',
                    ['displayname', 'mail', 'objectguid', 'samaccountname', 'givenname', 'sn', 'extensionattribute6', 'memberOf',]);
            } else {
                $ldapData = $ldap->getEntries('(&(objectClass=User)(sAMAccountName=' . $username . ')'.$groups.')',
                    ['displayname', 'mail', 'objectguid', 'samaccountname', 'givenname', 'sn', 'extensionattribute6', 'memberOf',]);
            }

            if (count($ldapData) > 1 && !empty($ldap->getSingleValue($ldapData, 'givenname')) && !empty($ldap->getSingleValue($ldapData, 'sn'))) {
                $model = new self;
                $model->object_guid = $ldap->getGUID($ldap->getSingleValue($ldapData, 'objectguid'));
                $model->username = $ldap->getSingleValue($ldapData, 'samaccountname');
                $model->first_name = $ldap->getSingleValue($ldapData, 'givenname');
                $model->last_name = $ldap->getSingleValue($ldapData, 'sn');
                $model->email = $ldap->getSingleValue($ldapData, 'mail');
                $model->display_name = $ldap->getSingleValue($ldapData, 'displayname');
                $model->status = self::STATUS_ACTIVE;
                $model->local_user = 0;
                $findIn = serialize($ldap->getMultiValue($ldapData, 'memberof'));
                $model->user_group_id = self::USERGROUP_USER;
                foreach (Yii::$app->params['login']['userGroups'] as $group => $role) {
                    if (strpos($findIn, $group) !== false) {
                        $model->user_group_id = $role;
                    }
                }

                if (!$model->save()) {
                    throw new Exception('Cannot save new user to database.');
                }

                return $model;
            }
        }

        return false;
    }

    public function  updateUserDataFromActiveDirectory()
    {
        //get LDAP component
        $ldap = yii::$app->ldap;

        $ldapData = $ldap->getEntries('(&(objectClass=User)(sAMAccountName=' . $this->username . '))', ['displayname', 'mail', 'givenname', 'sn', 'memberOf',]);

        $findIn = serialize($ldap->getMultiValue($ldapData, 'memberof'));
        $this->user_group_id = User::USERGROUP_USER;
        $this->status = User::STATUS_ACTIVE;
        if(count(Yii::$app->params['login']['userGroups']) > 0) {
            $this->status = User::STATUS_DELETED;
            $member_of_ad = [];
            foreach (Yii::$app->params['login']['userGroups'] as $group => $role) {
                if (strpos($findIn, $group) !== false) {
                    $this->user_group_id = $role;
                    $this->status = User::STATUS_ACTIVE;
                    $member_of_ad[] = $group;
                }
            }
            $this->setMemberOfAdFromArray($member_of_ad);
        }

        $this->email = $ldap->getSingleValue($ldapData, 'mail');
        $this->first_name = $ldap->getSingleValue($ldapData, 'givenname');
        $this->last_name = $ldap->getSingleValue($ldapData, 'sn');
        $this->display_name = $ldap->getSingleValue($ldapData, 'displayname');
        $this->updated_at = time();
        $this->save(false);
    }

    public static function getAllUsersOfCurrentUsersUsergroup()
    {
        if (!Yii::$app->user->isGuest) {
            return static::find()->where(['user_group_id' => Yii::$app->user->identity->user_group_id])->orderBy('display_name')->all();
        }

        return [];
    }

    public static function getAllUsersOfCurrentUsersUsergroupListData()
    {
        $users = self::getAllUsersOfCurrentUsersUsergroup();

        $listData = [];
        foreach ($users as $user) {
            $listData[$user->id] = $user->display_name;
        }

        return $listData;
    }

    public function getMemberOfAdAsArray()
    {
        $memberOfAd = explode(',', $this->member_of_ad);
        if (is_array($memberOfAd)) {
            return $memberOfAd;
        }

        return [];
    }

    public function setMemberOfAdFromArray(array $memberOfAd)
    {
        if (count($memberOfAd)) {
            $memberOfAd = array_unique($memberOfAd);
            $this->member_of_ad = implode(',', $memberOfAd);
            if (substr($this->member_of_ad, 0, 1) == ',') {
                $this->member_of_ad = substr($this->member_of_ad, 1);
            }
        }
    }

    public function getFullName()
    {
        return $this->first_name . ' ' . $this->last_name;
    }

    public static function getUsersListData()
    {
        return ArrayHelper::map(self::find()->orderBy('display_name')->all(), 'id', 'display_name');
    }
    
    public function isAdmin() {
        return $this->user_group_id == self::USERGROUP_ADMIN;
    }

}
