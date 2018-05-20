<?php namespace web\auth\cas;

use util\URI;

/**
 * Uses given URI as service URL
 */
class ServiceURL implements URL {
  private $uri;

  /** @param util.URI|string $uri */
  public function __construct($uri) {
    $this->uri= $uri instanceof URI ? $uri : new URI($uri);
  }
  
  /**
   * Resolves URI
   *
   * @param  web.Request $request
   * @return util.URI
   */
  public function resolve($request) {
    return $this->uri;
  }
}