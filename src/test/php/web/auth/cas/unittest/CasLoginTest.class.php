<?php namespace web\auth\cas\unittest;

use io\streams\MemoryInputStream;
use peer\http\HttpResponse;
use unittest\TestCase;
use web\Error;
use web\Request;
use web\Response;
use web\auth\cas\CasLogin;
use web\auth\cas\ServiceURL;
use web\auth\cas\UseRequest;
use web\filters\Invocation;
use web\io\TestInput;
use web\io\TestOutput;
use web\session\ForTesting;

class CasLoginTest extends TestCase {
  const SSO    = 'https://sso.example.com';
  const TICKET = 'ST-1856339-aA5Yuvrxzpv8Tau1cYQ7';

  private $sessions;

  /** @return void */
  public function setUp() {
    $this->sessions= new ForTesting();
  }

  /**
   * Creates a validation response
   *
   * @param  string $xml
   * @return peer.http.HttpResponse
   */
  public static function response($xml) {
    return new HttpResponse(new MemoryInputStream(sprintf(
      "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: %d\r\n\r\n%s",
      strlen($xml),
      $xml
    )));
  }

  /**
   * Calls filter
   * 
   * @param  string $uri
   * @param  [:string] $headers
   * @param  web.auth.cas.CasLogin $fixture
   * @return web.Response
   */
  private function filter($uri, $headers, $login) {
    $req= new Request(new TestInput('GET', $uri, $headers));
    $res= new Response(new TestOutput());
    $login->filter($req, $res, new Invocation(function($req, $res) { }));
    return $res;
  }

  /**
   * Asserts a given response redirects to a given SSO login
   *
   * @param  string $service
   * @param  web.Response $res
   * @throws unittest.AssertionFailedError
   */
  private function assertLoginWith($service, $res) {
    $this->assertEquals(self::SSO.'/login?service='.urlencode($service), $res->headers()['Location']);
  }

  #[@test]
  public function can_create() {
    new CasLogin(self::SSO, $this->sessions);
  }

  #[@test]
  public function redirects_to_login() {
    $res= $this->filter('/', [], new CasLogin(self::SSO, $this->sessions));
    $this->assertLoginWith('http://localhost/', $res);
  }

  #[@test]
  public function validates_ticket_then_redirects_to_self() {
    $res= $this->filter('/?ticket='.self::TICKET, [], newinstance(CasLogin::class, [self::SSO, $this->sessions], [
      'validate' => function($service, $ticket) {
        return CasLoginTest::response('
          <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
            <cas:authenticationSuccess>
              <cas:user>username</cas:user>
            </cas:authenticationSuccess>
          </cas:serviceResponse>
        ');
      }
    ]));
    $this->assertEquals('http://localhost/', $res->headers()['Location']);
  }

  #[@test, @expect(class= Error::class, withMessage= '/INVALID_TICKET: Ticket .+ not recognized/')]
  public function shows_error_when_ticket_cannot_be_validated() {
    $this->filter('/?ticket='.self::TICKET, [], newinstance(CasLogin::class, [self::SSO, $this->sessions], [
      'validate' => function($service, $ticket) {
        return CasLoginTest::response('
          <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
            <cas:authenticationFailure code="INVALID_TICKET">
              Ticket ST-1856339-aA5Yuvrxzpv8Tau1cYQ7 not recognized`
            </cas:authenticationFailure>
          </cas:serviceResponse>
        ');
      }
    ]));
  }

  #[@test, @expect(class= Error::class, withMessage= '/UNEXPECTED: .+/')]
  public function shows_error_when_validation_response_invalid() {
    $this->filter('/?ticket='.self::TICKET, [], newinstance(CasLogin::class, [self::SSO, $this->sessions], [
      'validate' => function($service, $ticket) {
        return CasLoginTest::response('
          <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
            <!-- Empty -->
          </cas:serviceResponse>
        ');
      }
    ]));
  }

  #[@test, @expect(class= Error::class, withMessage= '/FORMAT: Validation cannot be parsed/')]
  public function shows_error_when_validation_response_not_well_formed() {
    $this->filter('/?ticket='.self::TICKET, [], newinstance(CasLogin::class, [self::SSO, $this->sessions], [
      'validate' => function($service, $ticket) {
        return CasLoginTest::response('
          <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
          </cas:NOT_WELL_FORMED>
        ');
      }
    ]));
  }

  #[@test]
  public function stores_user_in_session() {
    $this->filter('/?ticket='.self::TICKET, [], newinstance(CasLogin::class, [self::SSO, $this->sessions], [
      'validate' => function($service, $ticket) {
        return CasLoginTest::response('
          <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
            <cas:authenticationSuccess>
              <cas:user>test</cas:user>
            </cas:authenticationSuccess>
          </cas:serviceResponse>
        ');
      }
    ]));
    $this->assertEquals(['username' => 'test'], current($this->sessions->all())->value('user'));
  }

  #[@test]
  public function stores_attributes_in_session() {
    $this->filter('/?ticket='.self::TICKET, [], newinstance(CasLogin::class, [self::SSO, $this->sessions], [
      'validate' => function($service, $ticket) {
        return CasLoginTest::response('
          <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
            <cas:authenticationSuccess>
              <cas:user>test</cas:user>
              <cas:attributes>
                <cas:firstname>John</cas:firstname>
                <cas:lastname>Doe</cas:lastname>
                <cas:email>jdoe@example.org</cas:email>
              </cas:attributes>
            </cas:authenticationSuccess>
          </cas:serviceResponse>
        ');
      }
    ]));
    $this->assertEquals(
      ['username' => 'test', 'firstname' => 'John', 'lastname' => 'Doe', 'email' => 'jdoe@example.org'],
      current($this->sessions->all())->value('user')
    );
  }

  #[@test]
  public function proceeds_with_invocation_if_logged_in() {
    $login= new CasLogin(self::SSO, $this->sessions);

    $session= $this->sessions->create();
    $session->register('user', ['username' => 'test']);

    $this->assertEquals('Invoked test', $login->filter(
      new Request(new TestInput('GET', '/', ['Cookie' => 'session='.$session->id()])),
      new Response(new TestOutput()),
      new Invocation(function($req, $res) { return 'Invoked '.$req->value('user')['username']; }
    )));
  }

  #[@test]
  public function redirects_to_login_if_session_id_non_existant() {
    $res= $this->filter('/', ['Cookie' => 'session=@does.not.exist@'], new CasLogin(self::SSO, $this->sessions));
    $this->assertLoginWith('http://localhost/', $res);
  }

  #[@test]
  public function redirects_to_login_if_session_invalid() {
    $session= $this->sessions->create();
    $session->destroy();

    $res= $this->filter('/', ['Cookie' => 'session='.$session->id()], new CasLogin(self::SSO, $this->sessions));
    $this->assertLoginWith('http://localhost/', $res);
  }

  #[@test]
  public function service_url_determined_from_request() {
    $res= $this->filter('/', [], new CasLogin(self::SSO, $this->sessions, new UseRequest()));
    $this->assertLoginWith('http://localhost/', $res);
  }

  #[@test]
  public function service_url_can_be_passed() {
    $res= $this->filter('/', [], new CasLogin(self::SSO, $this->sessions, new ServiceURL('https://example.com/')));
    $this->assertLoginWith('https://example.com/', $res);
  }
}