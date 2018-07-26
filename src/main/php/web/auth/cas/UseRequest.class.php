<?php namespace web\auth\cas;

/**
 * Uses request URI as service URL
 */
class UseRequest implements URL {
  
  /**
   * Resolves URI
   *
   * @param  web.Request $request
   * @return util.URI
   */
  public function resolve($request) {
    return $request->uri();
  }
}