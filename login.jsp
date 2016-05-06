<jsp:useBean id="authorize" class="bean.authorize" scope="session" />
<html>
<head>
<title>Login</title>
</head>
<body>
 <form action="/myop/login" method="post">
  Username<input name="username" type="text" maxlength="20"><p>
  Password<input name="password" type="password" maxlength="20"><p>
  <input type="hidden" name="response_type" value="<%= authorize.getResponsetype() %>">
  <input type="hidden" name="prompt" value="<%= authorize.getPrompt() %>">
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
