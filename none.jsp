<jsp:useBean id="authorize" class="bean.authorize" scope="session" />
<html>
<head>
<title>None</title>
</head>
<body onLoad="document.F.submit();">
 <form name="F" action="/myop/authorize" method="post">
  <input type="hidden" name="username" value="<%= authorize.getUsername() %>">
  <input type="hidden" name="password" value="<%= authorize.getPassword() %>">
  <input type="hidden" name="response_type" value="<%= authorize.getResponsetype() %>">
  <input type="hidden" name="prompt" value="<%= authorize.getPrompt() %>">
  <input type="hidden" name="login_hint" value="<%= authorize.getLoginhint() %>">
  <input type="hidden" name="max_age" value="<%= authorize.getMaxage() %>">
  <input type="hidden" name="client_id" value="<%= authorize.getClientid() %>">
  <input type="hidden" name="redirect_uri" value="<%= authorize.getRedirecturi() %>">
  <input type="hidden" name="scope" value="<%= authorize.getScope() %>">
  <input type="hidden" name="state" value="<%= authorize.getState() %>">
  <input type="hidden" name="nonce" value="<%= authorize.getNonce() %>">
  <input type="hidden" name="consent" value="<%= authorize.getConsent() %>">

 </form>
</body>
</html>
