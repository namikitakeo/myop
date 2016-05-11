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
 * >javac -cp servlet-api.jar;javax.json-1.0.4.jar userinfo.java
 *
 **************************************************************************/ 

import java.io.*;
import java.sql.*;
import javax.json.*;
import javax.json.stream.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class userinfo extends HttpServlet {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    response.setContentType("application/json; charset=UTF-8");
    PrintWriter out = response.getWriter();
    Connection conn = null;
    Statement stmt = null;
    ResultSet rs = null;
    JsonObjectBuilder value=null;
    String sql=null;
    String email=null;
    String phone_number=null;
    String name=null;
    String given_name=null;
    String family_name=null;
    String middle_name=null;
    String nickname=null;
    String address=null;
    String uid = request.getHeader("OIDC_CLAIM_openid");
    String scope = request.getHeader("OIDC_CLAIM_scope");
    if (scope == null) scope="openid";
    try {
        ServletContext context = this.getServletContext();
        String path = context.getRealPath("/WEB-INF/oauth2");
        Class.forName("org.apache.derby.jdbc.EmbeddedDriver").newInstance();
        conn = DriverManager.getConnection("jdbc:derby:"+path);
        stmt = conn.createStatement();
        sql = "SELECT * FROM profile WHERE uid='"+uid+"'";
        rs = stmt.executeQuery(sql);
        while(rs.next()){
            name = rs.getString("name");
            given_name = rs.getString("given_name");
            family_name = rs.getString("family_name");
            middle_name = rs.getString("middle_name");
            nickname = rs.getString("nickname");
            email = rs.getString("email");
            phone_number = rs.getString("phone_number");
            address = rs.getString("address");
        }
    }catch (Exception e){
        value = Json.createObjectBuilder().add("error_description", "database connect error").add("error", "server_error");
    }finally{
      try{
          if (rs != null) rs.close();
          if (stmt != null) stmt.close();
          if (conn != null) conn.close();
      }catch (SQLException e){
        value = Json.createObjectBuilder().add("error_description", "database close error").add("error", "server_error");
      }
    }
    if (value == null) value = Json.createObjectBuilder().add("error_description", "database select error uid="+uid).add("error", "server_error");
    if (uid != null) {
        value = Json.createObjectBuilder().add("sub", uid);
        if (name == null) name="";
        if (given_name == null) given_name="";
        if (family_name == null) family_name="";
        if (middle_name == null) middle_name="";
        if (nickname == null) nickname="";
        if (email == null) email="";
        if (phone_number == null) phone_number="";
        if (scope.contains("profile")) value = value.add("name", name).add("given_name", given_name).add("middle_name", middle_name).add("family_name", family_name).add("nickname", nickname);
        if (scope.contains("email")) value = value.add("email", email);
        if (scope.contains("phone")) value = value.add("phone_number", phone_number);
        if (scope.contains("address")) {
            if (address == null) {
                value = value.add("address", "");
            } else {
                JsonObjectBuilder array = Json.createObjectBuilder();
                JsonParser parser = Json.createParser(new StringReader(address));
                String keyname=null;
                while(parser.hasNext()){
                    JsonParser.Event event = parser.next();
                    switch(event){
                    case KEY_NAME:
                        keyname=parser.getString();
                        break;
                    case VALUE_STRING:
                        array = array.add(keyname, parser.getString());
                        break;
                    default:
                        break;
                    }
                }
                value = value.add("address", array);
            }
        }
    }
    out.println(value.build().toString());
  }
}

