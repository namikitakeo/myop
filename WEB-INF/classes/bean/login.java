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
 * >javac -cp servlet-api.jar bean\authorize.java bean\login.java bean\logout.java bean\consent.java bean\error.java
 *
 **************************************************************************/ 

package bean;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class login extends HttpServlet {
    ServletContext ctx = null;
    public void init(ServletConfig config) {
        synchronized(this) {
            if(ctx == null) {
                ctx = config.getServletContext();
            }
        }
    }
    public void service (HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
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
        RequestDispatcher rd = null;
        if (consent != null && consent.equals("true")) {
            rd = ctx.getRequestDispatcher("/consent.jsp");
        } else {
            HttpSession session = request.getSession(false);
            if (session == null) {
                session = request.getSession(true);
                authorize bean = new authorize(response_type, username, password, prompt, login_hint, max_age, client_id, redirect_uri, scope, state, nonce, consent);
                session.setAttribute("authorize", bean);
            } else {
                authorize cookie = (authorize)session.getAttribute("authorize");
                if (username == null && password == null && cookie != null) {
                    username = cookie.getUsername();
                    password = cookie.getPassword();
                }
                authorize bean = new authorize(response_type, username, password, prompt, login_hint, max_age, client_id, redirect_uri, scope, state, nonce, consent);
                session.setAttribute("authorize", bean);
            }
            if (username == null && password == null) rd = ctx.getRequestDispatcher("/login.jsp");
            else if (request.getMethod().equals("POST")) rd = ctx.getRequestDispatcher("/authorize");
            else rd = ctx.getRequestDispatcher("/none.jsp");
        }
        rd.forward(request, response);
    }
}

