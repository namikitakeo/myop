﻿<jsp:useBean id="authorize" class="bean.authorize" scope="session" />
<html>
<head>
<title>Login</title>
</head>
<body>
 <form action="/myop/login" method="post">
  <% if (authorize.getLoginhint()!=null && !authorize.getLoginhint().equals("null")) { %>
  <input type="hidden" name="username" value="<%= authorize.getLoginhint() %>">
  Username:<%= authorize.getLoginhint() %><p>
  <% } else { %>
  Username:<input name="username" type="text" maxlength="20"><p>
  <% } %>
  Password:<input name="password" type="password" maxlength="20"><p>
  <input type="hidden" name="response_type" value="<%= authorize.getResponsetype() %>">
  <input type="hidden" name="prompt" value="<%= authorize.getPrompt() %>">
  <input type="hidden" name="max_age" value="<%= authorize.getMaxage() %>">
  <input type="hidden" name="client_id" value="<%= authorize.getClientid() %>">
  <input type="hidden" name="redirect_uri" value="<%= authorize.getRedirecturi() %>">
  <input type="hidden" name="scope" value="<%= authorize.getScope() %>">
  <input type="hidden" name="state" value="<%= authorize.getState() %>">
  <input type="hidden" name="nonce" value="<%= authorize.getNonce() %>">
  <input type="hidden" name="consent" value="<%= authorize.getConsent() %>">
  <input type="submit" value="Login">
 </form>
</body>
</html>
