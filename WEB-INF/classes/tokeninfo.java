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
 * >javac -cp servlet-api.jar;javax.json-1.0.4.jar tokeninfo.java
 *
 **************************************************************************/ 

import java.io.*;
import java.sql.*;
import java.util.*;
import java.text.*;
import javax.json.*;
import javax.json.stream.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class tokeninfo extends HttpServlet {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    response.setContentType("application/json");
    PrintWriter out = response.getWriter();
    Connection conn = null;
    JsonObject value = null;
    String header = request.getHeader("Authorization");
    String access_token = request.getParameter("access_token");
    if (access_token==null && header!=null) access_token = header.substring(7);
    String uid = null;
    String scope = null;
    String issued_in = null;
    String client_id = null;
    String sql = null;
    int access_token_time = 60;
    try {
        ServletContext context = this.getServletContext();
        String path = context.getRealPath("/WEB-INF/oauth2");
        Class.forName("org.apache.derby.jdbc.EmbeddedDriver").newInstance();
        conn = DriverManager.getConnection("jdbc:derby:"+path);
        Statement stmt = conn.createStatement();
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
                if (keyname.equals("access_token")) access_token_time=parser.getInt();
                break;
            default:
                break;
            }
        }
        sql = "SELECT uid,scope,issued_in,client_id FROM session WHERE access_token='"+access_token+"' and {fn TIMESTAMPADD( SQL_TSI_SECOND,"+access_token_time+", issued_in)} > CURRENT_TIMESTAMP";
        ResultSet rs = stmt.executeQuery(sql);
        while(rs.next()){
            uid = rs.getString("uid");
            scope = rs.getString("scope");
            issued_in = rs.getString("issued_in");
            client_id = rs.getString("client_id");
        }
        value = Json.createObjectBuilder().add("error_description","Access Token not valid").add("error","invalid_request").build();
        if (uid != null) {
            JsonArrayBuilder scopes = Json.createArrayBuilder();
            String[] strs = scope.split(" ");
            for (int i=0; i < strs.length; i++)
                scopes.add(strs[i]);
            long datetime = new Timestamp(System.currentTimeMillis()).getTime() - Timestamp.valueOf(issued_in).getTime();
            value = Json.createObjectBuilder().add("issued_to", client_id).add("access_token", access_token).add("grant_type", "implicit").add("openid", uid).add("scope", scopes).add("token_type", "bearer").add("expires_in", (access_token_time * 1000 - datetime)/1000).build();
        }
        rs.close();
        stmt.close();
    }catch (Exception e){
        value = Json.createObjectBuilder().add("error_description", "database connect error").add("error", "server_error").build();
        out.print(value.toString());
        return;
    }finally{
      try{
        if (conn != null){
            conn.close();
        }
      }catch (SQLException e){
        value = Json.createObjectBuilder().add("error_description", "database close error").add("error", "server_error").build();
        out.print(value.toString());
        return;
      }
    }
    out.print(value.toString());
  }
}

