<jsp:useBean id="authorize" class="bean.authorize" scope="session" />
<html>
<head>
<title>Consent</title>
</head>
<body>
 <form action="/myop/authorize" method="post">
  <input type="hidden" name="username" value="<%= authorize.getUsername() %>">
  <input type="hidden" name="password" value="<%= authorize.getPassword() %>">
  <input type="hidden" name="response_type" value="<%= authorize.getResponsetype() %>">
  <input type="hidden" name="prompt" value="<%= authorize.getPrompt() %>">
  <input type="hidden" name="client_id" value="<%= authorize.getClientid() %>">
  <input type="hidden" name="redirect_uri" value="<%= authorize.getRedirecturi() %>">
  <input type="hidden" name="scope" value="<%= authorize.getScope() %>">
  <input type="hidden" name="state" value="<%= authorize.getState() %>">
  <input type="hidden" name="nonce" value="<%= authorize.getNonce() %>">
  <input type="hidden" name="consent" value="false">

scopes: <%= authorize.getScope() %><p>

uri: <%= authorize.getRedirecturi() %><p>

  <input type="submit" value="OK">
<% if (authorize.getState().equals("null")) { %>
  <input type="button" value="CANCEL" onClick="javascript:location.href='<%= authorize.getRedirecturi() %>#error=access_denied&error_description=User%20canceled%20the%20access.';">
<% } else { %>
  <input type="button" value="CANCEL" onClick="javascript:location.href='<%= authorize.getRedirecturi() %>#error=access_denied&error_description=User%20canceled%20the%20access.&state=<%= authorize.getState() %>';">
<% } %>

 </form>
</body>
</html>
