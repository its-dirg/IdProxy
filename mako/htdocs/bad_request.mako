<!DOCTYPE html>
<%inherit file="base.mako"/>

<%block name="title">
    Bad request
    ${parent.title()}
</%block>

<%block name="headline">
    <!-- Static navbar -->
    <nav class="navbar navbar-default" role="navigation">
        <div class="navbar-header">
          <a class="navbar-brand" href="#">Bad request</a>
        </div>
    </nav>
</%block>

<%block name="body">
        <div class="row" style="text-align: center">
            <div class="col-lg-12">Your request can not be handled by the identity server.</div>
        </div>
        <div class="row" style="text-align: center">
            <div class="col-lg-12">Please contact the technical support for the service you are trying to get access to.</div>
        </div>
        <div class="row" style="text-align: center">
            <div class="col-lg-12">Please state this id to your support: ${log_id}</div>
        </div>

</%block>