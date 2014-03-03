<!DOCTYPE html>
<%inherit file="base.mako"/>

<%block name="title">
    Logout
    ${parent.title()}
</%block>

<%block name="headline">
    <!-- Static navbar -->
    <nav class="navbar navbar-default" role="navigation">
        <div class="navbar-header">
          <a class="navbar-brand" href="#">Logout</a>
        </div>
    </nav>
</%block>

<%block name="body">
        <div class="row">
            <div class="col-lg-2">&nbsp;</div>
            <div class="col-lg-8">&nbsp;</div>
            <div class="col-lg-2">&nbsp;</div>
        </div>
        <div class="row">
            <div class="col-lg-2">&nbsp;</div>
            <div class="col-lg-8">Do you want to logout from the provider and end your SSO session?</div>
            <div class="col-lg-2">&nbsp;</div>
        </div>
        <div class="row">
            <div class="col-lg-2">&nbsp;</div>
            <div class="col-lg-2">
                <form class="form-signin" action="${action}" method="get">
                    <input type="hidden" name="acr_values" value="${acr_values}"/>
                    <input type="hidden" name="id_token_hint" value="${id_token_hint}"/>
                    <input type="hidden" name="post_logout_redirect_uri" value="${post_logout_redirect_uri}"/>
                    <input type="hidden" name="key" value="${key}"/>
                    <button class="btn btn-lg btn-primary btn-block" type="submit">Yes</button>
                </form>
            </div>
            <div class="col-lg-4">&nbsp;</div>
            <div class="col-lg-2">
                <form class="form-signin" action="${redirect}" method="get">
                    <button class="btn btn-lg btn-primary btn-block" type="submit">No</button>
                </form>
            </div>
            <div class="col-lg-2">&nbsp;</div>
        </div>
</%block>