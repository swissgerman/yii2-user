<?php

namespace samkoch\yii2user\controllers;

use Yii;
use yii\web\Controller;
use yii\helpers\Url;
use samkoch\yii2user\models\LoginForm;
use samkoch\activitylog\ActivityLog;

class SiteController extends Controller
{
    /**
     * Login action.
     *
     * @return string
     */
    public function actionLogin()
    {
        $loginMode = 'local';

        //redirect to sso action if ssoUser is not set in session yet
        if ((!isset(YII::$app->params['login']['enableSSO']) ||  YII::$app->params['login']['enableSSO'] == true)
            && (!isset($_GET['ssouser']) || !isset($_GET['ssodomain']) || !isset($_GET['timestamp']) || !isset($_GET['auth']))
            && !Yii::$app->session['ssoLoginAttempted'] && !isset(Yii::$app->session['logout'])
        ) {
            Yii::$app->session['ssoLoginAttempted'] = true;
            $this->redirect('/sso/?returnUrl=' . urlencode(Url::current([], true)));

            Yii::$app->end();
        }

        if (!Yii::$app->user->isGuest) {
            return $this->goHome();
        }

        $model = new LoginForm();
        $params = Yii::$app->request->post();

        if (isset($_GET['ssouser']) && isset($_GET['ssodomain']) && isset($_GET['timestamp']) && isset($_GET['auth']) && !isset(Yii::$app->session['logout'])) {
            $knownHash = hash('sha256', $_GET['ssouser'] . $_GET['ssodomain'] . $_GET['timestamp'] . yii::$app->params['ssoAuthSecretKey']);
            if (hash_equals($knownHash, $_GET['auth'])) {
                Yii::$app->session['authSsoLogin'] = true;

                $params = [
                    'LoginForm' => [
                        'username' => $_GET['ssouser'],
                        'password' => $_GET['ssouser'],
                    ]
                ];
                $loginMode = 'sso';

                if (!$model) {
                    $model = new LoginForm();
                }
            }
        }

        if ($model->load($params) && $model->login()) {
            //remove password from log params array
            $logParams = $params;
            $logParams['LoginForm']['password'] = '***';

            //log activity
            ActivityLog::log('Login', 'User logged in', $model, null,
                'Login mode: ' . $loginMode . PHP_EOL . 'Form contents: ' . PHP_EOL . print_r($logParams, true));
            return $this->goBack();
        } else {
            return $this->render('login', [
                'model' => $model,
            ]);
        }
    }

    /**
     * Logout action.
     *
     * @return string
     */
    public function actionLogout()
    {
        //log activity
        ActivityLog::log('Logout', 'User logged out', Yii::$app->user);

        Yii::$app->user->logout(false);
        Yii::$app->session['logout'] = true;

        return $this->goHome();
    }

}
