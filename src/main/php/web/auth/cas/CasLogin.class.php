<?php namespace web\auth\cas;

use web\Cookie;
use web\Filter;
use web\Error;
use peer\http\HttpConnection;
use xml\XMLFormatException;
use xml\dom\Document;
use xml\parser\XMLParser;
use xml\parser\StreamInputSource;
use web\session\Sessions;

/**
 * CAS Login filter
 *
 * @see   https://apereo.github.io/cas/4.1.x/protocol/CAS-Protocol-Specification.html
 * @test  xp://web.auth.cas.unittest.CasLoginTest
 */
class CasLogin implements Filter {
  private $sso, $sessions;

  /**
   * Creates a new instance with a given SSO base url and sessions implementation
   *
   * @param  string $sso
   * @param  web.session.Sessions $sessions
  */
  public function __construct($sso, Sessions $sessions) {
    $this->sso= rtrim($sso, '/');
    $this->sessions= $sessions;
  }

  /**
   * Validates a CAS ticket
   *
   * @param  string $ticket
   * @param  string $service
   * @return peer.http.HttpResponse
   */
  protected function validate($ticket, $service) {
    return (new HttpConnection($this->sso.'/serviceValidate'))->get([
      'ticket'  => $ticket,
      'service' => $service
    ]);
  }

  /**
   * Filter
   *
   * @param  web.Request $request
   * @param  web.Response $response
   * @param  web.Invocation $invocation
   * @return var
   */
  public function filter($request, $response, $invocation) {

    // Validate ticket, then relocate to self without ticket parameter
    if ($ticket= $request->param('ticket')) {
      $service= $request->uri()->using()->param('ticket', null)->create();

      $validate= $this->validate($ticket, $service);
      if (200 !== $validate->statusCode()) {
        throw new Error($validate->statusCode(), $validate->message());
      }

      $result= new Document();
      try {
        (new XMLParser())->withCallback($result)->parse(new StreamInputSource($validate->in()));
      } catch (XMLFormatException $e) {
        throw new Error(500, 'FORMAT: Validation cannot be parsed', $e);
      }

      if ($failure= $result->getElementsByTagName('cas:authenticationFailure')) {
        throw new Error(500, $failure[0]->getAttribute('code').': '.trim($failure[0]->getContent()));
      } else if (!($success= $result->getElementsByTagName('cas:authenticationSuccess'))) {
        throw new Error(500, 'UNEXPECTED: '.$result->getSource());
      }

      $user= ['username' => $result->getElementsByTagName('cas:user')[0]->getContent()];
      if ($attr= $result->getElementsByTagName('cas:attributes')) {
        foreach ($attr[0]->getChildren() as $child) {
          $user[str_replace('cas:', '', $child->getName())]= $child->getContent();
        }
      }

      $session= $this->sessions->create();
      try {
        $session->register('user', $user);
        $response->cookie((new Cookie('session', $session->id()))->maxAge($this->sessions->duration()));
      } finally {
        $session->close();
      }

      $response->answer(302);
      $response->header('Location', $service);
      return;
    }

    // Handle session
    if ($session= $this->sessions->locate($request->cookie('session'))) {
      try {
        if ($session->valid()) {
          $request->pass('user', $session->value('user'));
          return $invocation->proceed($request, $response);
        }
      } finally {
        $session->close();
      }
    }

    $response->answer(302);
    $response->header('Location', $this->sso.'/login?service='.urlencode($request->uri()));
  }
}