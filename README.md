CAS authentication for the XP Framework
========================================================================

[![Build Status on TravisCI](https://secure.travis-ci.org/xp-forge/auth-cas.png)](http://travis-ci.org/xp-forge/auth-cas)
[![XP Framework Module](https://raw.githubusercontent.com/xp-framework/web/master/static/xp-framework-badge.png)](https://github.com/xp-framework/core)
[![BSD Licence](https://raw.githubusercontent.com/xp-framework/web/master/static/licence-bsd.png)](https://github.com/xp-framework/core/blob/master/LICENCE.md)
[![Required PHP 5.6+](https://raw.githubusercontent.com/xp-framework/web/master/static/php-5_6plus.png)](http://php.net/)
[![Supports PHP 7.0+](https://raw.githubusercontent.com/xp-framework/web/master/static/php-7_0plus.png)](http://php.net/)
[![Latest Stable Version](https://poser.pugx.org/xp-forge/auth-cas/version.png)](https://packagist.org/packages/xp-forge/auth-cas)

Example
-------

```php
use web\{Application, Filters};
use web\auth\cas\CasLogin;
use web\session\InFileSystem;

class App extends Application {

  public function routes() {
    $login= new CasLogin('https://sso.example.com/', new InFileSystem('/var/tmp/sessions'));

    return new Filters([$login], [
      '/' => function($req, $res) {
        $res->answer(200);
        $res->send('Hello @'.$req->value('user')['username'], 'text/plain');
      }
    ]);
  }
}
```

Proxies
-------

The service URL is calculated from the request URI by default. However, if the service is behind a reverse proxy, the front-facing URL needs to be passed in.

```php
$login= new CasLogin('https://sso.example.com/', $sessions, new ServiceURL('https://app.example.com/'));
```
