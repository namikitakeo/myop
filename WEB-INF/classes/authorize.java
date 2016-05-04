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
 * >javac -cp servlet-api.jar;commons-lang3-3.4.jar;jjwt-0.6.0.jar authorize.java
 *
 **************************************************************************/ 

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

import java.sql.*;
import java.net.*;
import java.text.*;
import org.apache.commons.lang3.RandomStringUtils;

import java.util.*;
import java.security.*;
import java.security.spec.*;
import io.jsonwebtoken.*;

public class authorize extends HttpServlet {
    public void service (HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        PrintWriter out = response.getWriter();
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        String response_type = request.getParameter("response_type");
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        String prompt = request.getParameter("prompt");
        String client_id = request.getParameter("client_id");
        String redirect_uri = request.getParameter("redirect_uri");
        String scope = request.getParameter("scope");
        String state = request.getParameter("state");
        String nonce = request.getParameter("nonce");
        String client_scope=null;
        String access_token=null;
        String id_token=null;
        String db_password=null;
        String path = null;
        String sql = null;
        String uri = null;
        String issuer = null;
        if (scope == null) scope="openid";
        try {
            ServletContext context = this.getServletContext();
            path = context.getRealPath("/WEB-INF/oauth2");
            Class.forName("org.apache.derby.jdbc.EmbeddedDriver").newInstance();
            conn = DriverManager.getConnection("jdbc:derby:"+path);
            stmt = conn.createStatement();
            sql = "SELECT scope FROM client WHERE client_id='"+client_id+"'";
            rs = stmt.executeQuery(sql);
            while(rs.next()){
                client_scope = rs.getString("scope");
            }
            sql = "SELECT db_password FROM profile WHERE uid='"+username+"'";
            rs = stmt.executeQuery(sql);
            while(rs.next()){
                db_password = rs.getString("db_password");
            }
            java.util.Date dt = new java.util.Date();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String currentTime = sdf.format(dt);
            access_token = RandomStringUtils.randomAlphanumeric(32);
            if (client_scope != null) {
                if (db_password != null && db_password.equals(password) && client_scope.contains(scope)) {
                    sql = "insert into session(uid,access_token,issued_in,scope,client_id) values ('"+username+"','"+access_token+"','"+currentTime+"','"+scope+"','"+client_id+"')";
                    stmt.executeUpdate(sql);
                    rs.close();
                    stmt.close();
                    conn.close();
                    byte[] cipher_byte;
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    md.update(access_token.getBytes());
                    cipher_byte = md.digest();
                    String at_hash = Base64.getEncoder().encodeToString(cipher_byte);
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
                    exp.add(Calendar.SECOND, 60);
                    path = context.getRealPath("/WEB-INF/openid-configuration.json");
                    File json = new File(path);
                    BufferedReader br = new BufferedReader(new FileReader(json));
                    String str = br.readLine();
                    String[] strs = str.split("\"");
                    issuer=strs[11];
                    if (nonce == null || nonce.equals("null")) {
                        if (response_type.contains("id_token")) {
                            response.sendRedirect("/myop/error");
                            return;
                        }
                    } else {
                        id_token = Jwts.builder().setIssuer(issuer).setAudience("OpenIG").claim("nonce",nonce).claim("at_hash",at_hash).setSubject(username).setExpiration(exp.getTime()).setIssuedAt(Calendar.getInstance().getTime()).signWith(SignatureAlgorithm.RS256,privateKey).compact();
                    }
                    uri = redirect_uri;
                    if (response_type.equals("token")) uri += "#access_token="+access_token+"&token_type=Bearer&expires_in=60";
                    if (response_type.equals("id_token")) uri += "#id_token="+id_token;
                    if (response_type.equals("token id_token")) uri += "#access_token="+access_token+"&token_type=Bearer&expires_in=60"+"&id_token="+id_token;
                    if (state != null && !state.equals("null")) uri += "&state="+state;
                    response.sendRedirect(uri);
                    return;
                }
            }
        }catch (Exception e){
            ;
        }finally{
            try{
                if (conn != null) {
                    rs.close();
                    stmt.close();
                    conn.close();
                }
            }catch (SQLException e){
                ;
            }
        }
        if (client_scope != null && redirect_uri != null && response_type != null && (response_type.equals("token") || response_type.equals("id_token") || response_type.equals("token id_token"))) {
            uri = "/myop/login?response_type="+URLEncoder.encode(response_type,"UTF-8")+"&scope="+URLEncoder.encode(scope,"UTF-8")+"&client_id="+client_id+"&redirect_uri="+URLEncoder.encode(redirect_uri,"UTF-8");
            if (prompt != null && !prompt.equals("null")) uri += "&prompt="+prompt;
            if (state != null && !state.equals("null")) uri += "&state="+state;
            if (nonce != null && !nonce.equals("null")) uri += "&nonce="+nonce;
            response.sendRedirect(uri);
        } else {
            response.sendRedirect("/myop/error");
        }
    }
}

