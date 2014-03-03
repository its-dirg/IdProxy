<!DOCTYPE html>
<%inherit file="base.mako"/>

<%block name="title">
    Login
    ${parent.title()}
</%block>

<%block name="headline">
    <!-- Static navbar -->
    <nav class="navbar navbar-default" role="navigation">
        <div class="navbar-header">
          <a class="navbar-brand" href="#">Login</a>
        </div>
    </nav>
</%block>

<%block name="body">
        <form class="form-signin" action="${action}" method="get">
            <input type="hidden" name="query" value="${query}"/>
            <div class="row">
                <div class="col-lg-12"><input type="text" id="login" name="login" value="${login}" class="form-control" placeholder="Username" autofocus></div>
            </div>
            <div class="row">
                <div class="col-lg-12"><input type="password" id="otp" name="otp" value="${otp}" class="form-control" placeholder="OTP"></div>
            </div>
            <button class="btn btn-lg btn-primary btn-block" type="submit">Login</button>
        </form>
</%block>