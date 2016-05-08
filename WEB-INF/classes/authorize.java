/*
 * Licensed to the Apache Software Foundation (ASF) under one 
 * or more contributor license agreements.  See the NOTICE file 
 * distributed with this work for additional information 
 * regarding copyright ownership.  The ASF licenses this file 
 * to you under the Apache License, Version 2.0 (the 
 * "License"); you may not use this file except in compliance 
 * with the License.  You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 * 
 * Unless required by applicable law or agreed to in writing, 
 * software distributed under the License is distributed on an 
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY 
 * KIND, either express or implied.  See the License for the 
 * specific language governing permissions and limitations 
 * under the License. 
 */ 

/*************************************************************************** 
 *
 * DISCLAIMER OF WARRANTIES: 
 * 
 * THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT 
 * ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING, 
 * WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT, 
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY 
 * WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE 
 * USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET 
 * YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE 
 * WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF 
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 * 
 * @Author: Takeo Namiki - takeo.namiki@gmail.com 
 * 
 * >javac -cp servlet-api.jar;commons-lang3-3.4.jar;jjwt-0.6.0.jar;javax.json-1.0.4.jar;log4j-api-2.5.jar authorize.java
 *
 **************************************************************************/ 

import java.io.*;
import java.sql.*;
import java.net.*;
import java.text.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.json.*;
import javax.json.stream.*;
import javax.servlet.*;
import javax.servlet.http.*;
import io.jsonwebtoken.*;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.logging.log4j.*;

public class authorize extends HttpServlet {
    public void service (HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Logger logger = LogManager.getLogger(authorize.class);
        logger.trace("START");
        PrintWriter out = response.getWriter();
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        HttpSession session = request.getSession(false);
        String response_type = request.getParameter("response_type");
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        String prompt = request.getParameter("prompt");
        String login_hint = request.getParameter("login_hint");
        String max_age = request.getParameter("max_age");
        String client_id = request.getParameter("client_id");
        String redirect_uri = request.getParameter("redirect_uri");
        String scope = request.getParameter("scope");
        String state = request.getParameter("state");
        String nonce = request.getParameter("nonce");
        String consent = request.getParameter("consent");
        String client_scope=null;
        String access_token=null;
        String id_token=null;
        String passwd=null;
        String db_redirect_uri=null;
        String path = null;
        String sql = null;
        String uri = null;
        String issuer = null;
        boolean redirect_uri_check = true;
        int access_token_time = 60;
        String kit="public.key";
        if (scope == null) {
            scope="openid";
        } else if (scope.equals("consent")) {
            scope=null;
            if (null != request.getParameter("openid")) {
                scope = "openid";
                if (null != request.getParameter("profile")) scope += " profile";
                if (null != request.getParameter("email")) scope += " email";
                if (null != request.getParameter("phone")) scope += " phone";
                if (null != request.getParameter("address")) scope += " address";
            }
        }
        logger.trace(scope);
        if (prompt != null && prompt.contains("login") && consent == null && session != null) session.invalidate();
        try {
            ServletContext context = this.getServletContext();
            path = context.getRealPath("/WEB-INF/oauth2");
            Class.forName("org.apache.derby.jdbc.EmbeddedDriver").newInstance();
            conn = DriverManager.getConnection("jdbc:derby:"+path);
            stmt = conn.createStatement();
            logger.trace("connect()");
            sql = "SELECT scope, redirect_uri FROM client WHERE client_id='"+client_id+"'";
            rs = stmt.executeQuery(sql);
            while(rs.next()){
                client_scope = rs.getString("scope");
                db_redirect_uri = rs.getString("redirect_uri");
            }
            logger.trace(sql);
            if (redirect_uri == null) redirect_uri=db_redirect_uri;
            sql = "SELECT passwd FROM profile WHERE uid='"+username+"'";
            rs = stmt.executeQuery(sql);
            while(rs.next()){
                passwd = rs.getString("passwd");
            }
            logger.trace(sql);
            String keyname = null;
            path = context.getRealPath("/WEB-INF/config.json");
            InputStream input = new FileInputStream(path);
            JsonParser parser = Json.createParser(input);
            while(parser.hasNext()){
                JsonParser.Event event = parser.next();
                switch(event){
                case KEY_NAME:
                    keyname=parser.getString();
                    break;
                case VALUE_NUMBER:
                    access_token_time=parser.getInt();
                    break;
                case VALUE_TRUE:
                    redirect_uri_check=true;
                    break;
                case VALUE_FALSE:
                    redirect_uri_check=false;
                    break;
                case VALUE_STRING:
                    if (keyname.equals("issuer")) issuer=parser.getString();
                    if (keyname.equals("kit")) kit=parser.getString();
                    break;
                default:
                    break;
                }
            }
            java.util.Date dt = new java.util.Date();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String currentTime = sdf.format(dt);
            if (client_scope != null && passwd != null) {
                byte[] cipher_byte;
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(password.getBytes());
                cipher_byte = md.digest();
                String sha256_password = Base64.getEncoder().withoutPadding().encodeToString(cipher_byte);
                StringTokenizer strToken = new StringTokenizer(scope, " ");
                while(strToken.hasMoreTokens()) { 
                    String token = strToken.nextToken().toString();
                    logger.trace(token);
                    if (!client_scope.contains(token))
                        throw new Exception("out of scope");
                }
                if (passwd.contains(sha256_password) && (!redirect_uri_check || db_redirect_uri.equals(redirect_uri))) {
                    if (prompt != null && prompt.contains("consent") && !consent.equals("false")) {
                        username="null";
                        password="null";
                        consent="true";
                        throw new Exception("consent is true");
                    }
                    access_token = RandomStringUtils.randomAlphanumeric(32);
                    logger.trace(access_token);
                    sql = "insert into session(uid,access_token,issued_in,scope,client_id) values ('"+username+"','"+access_token+"','"+currentTime+"','"+scope+"','"+client_id+"')";
                    stmt.executeUpdate(sql);
                    md.update(access_token.getBytes());
                    cipher_byte = md.digest();
                    byte[] half_cipher_byte = Arrays.copyOf(cipher_byte, (cipher_byte.length / 2));
                    String at_hash = Base64.getEncoder().withoutPadding().encodeToString(half_cipher_byte);
                    path = context.getRealPath("/WEB-INF/private.der");
                    File filePrivateKey = new File(path);
                    FileInputStream fis = new FileInputStream(path);
                    byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
                    fis.read(encodedPrivateKey);
                    fis.close();
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
                    PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
                    Calendar exp = Calendar.getInstance();
                    exp.add(Calendar.SECOND, access_token_time);
                    if (nonce == null || nonce.equals("null")) {
                        if (response_type.contains("id_token")) {
                            uri = redirect_uri;
                            uri += "#error=invalid_request&error_description=nonce%20is%20not%20valid.";
                            response.sendRedirect(uri);
                            logger.info(uri);
                            return;
                        }
                    } else {
                        id_token = Jwts.builder().setHeaderParam("alg", "RS256").setHeaderParam("typ", "JWT").setHeaderParam("kid", kit).setIssuer(issuer).claim("at_hash",at_hash).setSubject(username).setAudience(client_id).claim("nonce",nonce).setSubject(username).setExpiration(exp.getTime()).setIssuedAt(Calendar.getInstance().getTime()).claim("auth_time",String.valueOf(Calendar.getInstance().getTime().getTime()).substring(0,10)).signWith(SignatureAlgorithm.RS256,privateKey).compact();
                        logger.trace(id_token);
                    }
                    uri = redirect_uri;
                    if (response_type.equals("token")) uri += "#access_token="+access_token+"&token_type=bearer&expires_in="+access_token_time;
                    if (response_type.equals("id_token")) uri += "#id_token="+id_token;
                    if (response_type.equals("token id_token") || response_type.equals("id_token token")) uri += "#access_token="+access_token+"&token_type=bearer&expires_in="+access_token_time+"&id_token="+id_token;
                    if (state != null && !state.equals("null")) uri += "&state="+state;
                    response.sendRedirect(uri);
                    logger.info(uri);
                    return;
                }
            }
        }catch (Exception e){
            logger.trace(e.getMessage());
        }finally{
            try{
                if (conn != null) {
                    rs.close();
                    stmt.close();
                    conn.close();
                    logger.trace("close()");
                }
            }catch (SQLException e){
                logger.trace(e.getMessage());
            }
        }
        if (redirect_uri != null || redirect_uri.equals("null")) uri = redirect_uri;
        else uri = "/myop/error";
        if (username != null && !username.equals("null") && password != null && !password.equals("null")) {
            uri += "#error=access_denied&error_description=User%20authentication%20failed.";
            session = request.getSession(false);
            if (session != null) session.invalidate();
        } else if (scope == null) {
            uri += "#error=invalid_scope&error_description=The%20scope%20value%20is%20not%20supported.";
        } else if (client_scope == null || client_scope.equals("null")) {
            uri += "#error=unauthorized_clienti&error_description=Client%20authentication%20failed.";
	} else if (response_type == null || response_type.equals("null") || !(response_type.equals("token") || response_type.equals("id_token") || response_type.equals("token id_token") || response_type.equals("id_token token"))) {
            uri += "#error=unsupported_response_type&error_description==The%20response_type%20value%20%22"+response_type+"%22%20is%20not%20supported.";
        } else if (redirect_uri_check && !db_redirect_uri.equals(redirect_uri)) {
            uri += "#error=invalid_request&error_description=redirect_uri%20is%20not%20valid.";
        } else {
            uri = "/myop/login?response_type="+URLEncoder.encode(response_type,"UTF-8")+"&client_id="+client_id+"&redirect_uri="+URLEncoder.encode(redirect_uri,"UTF-8")+"&scope="+URLEncoder.encode(scope,"UTF-8");
            if (nonce != null && !nonce.equals("null")) uri += "&nonce="+nonce;
            if (prompt != null && !prompt.equals("null")) uri += "&prompt="+prompt;
            if (login_hint != null && !login_hint.equals("null")) uri += "&login_hint="+login_hint;
            if (max_age != null && !max_age.equals("null")) uri += "&max_age="+max_age;
            if (consent != null && consent.equals("true")) uri += "&consent="+consent;
        }
        if (state != null && !state.equals("null")) uri += "&state="+state;
        response.sendRedirect(uri);
        logger.info(uri);
        logger.trace("END");
    }
}

