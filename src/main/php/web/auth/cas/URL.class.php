<?php namespace web\auth\cas;

interface URL {
  
  /**
   * Resolves URI
   *
   * @param  web.Request $request
   * @return util.URI
   */
  public function resolve($request);
}