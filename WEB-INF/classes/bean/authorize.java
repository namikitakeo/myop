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

import java.io.Serializable;

public class authorize implements Serializable {
    private String response_type = "";
    private String username = "";
    private String password = "";
    private String prompt = "";
    private String login_hint = "";
    private String max_age = "";
    private String client_id = "";
    private String redirect_uri = "";
    private String scope = "";
    private String state = "";
    private String nonce = "";
    private String consent = "";
    public authorize() {
        this.response_type = "";
        this.username = "";
        this.password = "";
        this.prompt = "";
        this.login_hint = "";
        this.max_age = "";
        this.client_id = "";
        this.redirect_uri = "";
        this.scope = "";
        this.state = "";
        this.nonce = "";
        this.consent = "";
    }
    public authorize(String response_type, String username, String password, String prompt, String login_hint, String max_age, String client_id, String redirect_uri, String scope, String state, String nonce, String consent) {
        this.response_type = response_type;
        this.username = username;
        this.password = password;
        this.prompt = prompt;
        this.login_hint = login_hint;
        this.max_age = max_age;
        this.client_id = client_id;
        this.redirect_uri = redirect_uri;
        this.scope = scope;
        this.state = state;
        this.nonce = nonce;
        this.consent = consent;
    }
    public String getResponsetype() { return response_type; }
    public String getUsername() { return username; }
    public String getPassword() { return password; }
    public String getPrompt() { return prompt; }
    public String getLoginhint() { return login_hint; }
    public String getMaxage() { return max_age; }
    public String getClientid() { return client_id; }
    public String getRedirecturi() { return redirect_uri; }
    public String getScope() { return scope; }
    public String getState() { return state; }
    public String getNonce() { return nonce; }
    public String getConsent() { return consent; }
    public void setResponsetype(String s) { response_type = s; }
    public void setUsername(String s) { username = s; }
    public void setPassword(String s) { password = s; }
    public void setPrompt(String s) { prompt = s; }
    public void setLoginhint(String s) { login_hint = s; }
    public void setMaxage(String s) { max_age = s; }
    public void setClientid(String s) { client_id = s; }
    public void setRedirecturi(String s) { redirect_uri = s; }
    public void setScope(String s) { scope = s; }
    public void setState(String s) { state = s; }
    public void setNonce(String s) { nonce = s; }
    public void setConsent(String s) { consent = s; }
}

