/*
(c) 2024 Scot Watson  All Rights Reserved
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

const initPageTime = performance.now();

const asyncWindow = new Promise(function (resolve, reject) {
  window.addEventListener("load", function (evt) {
    resolve(evt);
  });
});

const asyncOAuth2 = import("./OAuth2.js");

(async function () {
  try {
    const modules = await Promise.all( [ asyncWindow, asyncOAuth2 ] );
    start(modules);
  } catch (e) {
    console.error(e);
    throw e;
  }
})();

// Creates a GET Request to the specified endpoint
function createRequestGET(endpoint, headers) {
  return new self.Request(endpoint, {
    method: "GET",
    headers: headers,
    mode: "cors",
    credentials: "same-origin",
    cache: "default",
    redirect: "follow",
    referrer: "about:client",
    referrerPolicy: "",
    integrity: "",
    keepalive: "",
    signal: null,
    priority: "auto",
  });
}

// Creates a POST Request to the specified endpoint
function createRequestPOST(endpoint, body, headers) {
  return new self.Request(endpoint, {
    method: "POST",
    headers: headers,
    body: body,
    mode: "cors",
    credentials: "same-origin",
    cache: "default",
    redirect: "follow",
    referrer: "about:client",
    referrerPolicy: "",
    integrity: "",
    keepalive: "",
    signal: null,
    priority: "auto",
  });
}

const selfURL = new self.URL(window.location);
const selfURLParams = selfURL.searchParams;
const selfURLFragment = selfURL.hash.substring(1);

function start([ evtWindow, OAuth2 ]) {
  try {
    const pClientId = document.createElement("p");
    pClientId.append("Client ID: ");
    const inpClientId = document.createElement("input");
    inpClientId.type = "text";
    pClientId.appendChild(inpClientId);
    document.body.appendChild(pClientId);
    const pTokenEndpoint = document.createElement("p");
    pTokenEndpoint.append("Token Endpoint: ");
    const inpTokenEndpoint = document.createElement("input");
    inpTokenEndpoint.type = "text";
    pTokenEndpoint.appendChild(inpTokenEndpoint);
    document.body.appendChild(pTokenEndpoint);

    function createTokenManagement(args) {
      const div = document.createElement("div");
      const myTokenManagement = new OAuth2.TokenManagement(args);
      const pClientId = document.createElement("p");
      pClientId.append("Client ID: " + args.clientId)
      div.appendChild(pClientId);
      const pTokenEndpoint = document.createElement("p");
      pTokenEndpoint.append("Token Endpoint: " + args.tokenEndpoint)
      div.appendChild(pTokenEndpoint);
      async function revokeTokens() {
        const revokeEndpoint = window.prompt("Enter the revoke endpoint:");
        const req = createRequestPOST(revokeEndpoint, null, []);
        const resp = await dropboxTokenManagement.fetch(req);
        console.log(resp);
        if (resp.status === 200) {
          console.log("Tokens Revoked");
          dropboxTokenManagement.setTokens({});
        } else {
          console.log("Tokens Not Revoked");
        }
      }
      const btnRevokeTokens = document.createElement("button");
      btnRevokeTokens.innerHTML = "Revoke Tokens";
      btnRevokeTokens.addEventListener("click", function (evt) {
        revokeTokens();
      });
      div.appendChild(btnRevokeTokens);
      const pAccessToken = document.createElement("p");
      const btnSetAccessToken = document.createElement("button");
      btnSetAccessToken.innerHTML = "Set Access Token";
      btnSetAccessToken.addEventListener("click", function (evt) {
        newAccessToken = window.prompt("Enter the access token: ");
        if (newAccessToken) {
          myTokenManagement.setTokens({
            accessToken: newAccessToken,
            refreshToken: myTokenManagement.getRefreshToken(),
            tokenType: myTokenManagement.getTokenType(),
            expiryDate: new Date(Date.now() + 14400 * 1000),
          });
        }
      });
      pAccessToken.appendChild(btnSetAccessToken);
      const btnGetImplicitAccessToken = document.createElement("button");
      btnGetImplicitAccessToken.innerHTML = "Get Implicit Access Token";
      btnGetImplicitAccessToken.addEventListener("click", function (evt) {
        const authorizationEndpoint = window.prompt("Enter the authorization endpoint:");
        myTokenManagement.retrieveTokenImplicitAccess({
          authorizationEndpoint: authorizationEndpoint,
        });
      });
      pAccessToken.appendChild(btnGetImplicitAccessToken);
      const btnGetPKCEAccessToken = document.createElement("button");
      btnGetPKCEAccessToken.innerHTML = "Get PKCE Access Token";
      btnGetPKCEAccessToken.addEventListener("click", function (evt) {
        const authorizationEndpoint = window.prompt("Enter the authorization endpoint:");
        myTokenManagement.retrieveTokenPKCEAccess({
          authorizationEndpoint: authorizationEndpoint,
        });
      });
      pAccessToken.appendChild(btnGetPKCEAccessToken);
      const spanAccessToken = document.createElement("span");
      spanAccessToken.append(myTokenManagement.getAccessToken());
      myTokenManagement.setCallbackAccessToken(function (strToken) {
        spanAccessToken.innerHTML = "";
        spanAccessToken.append(strToken);
      });
      pAccessToken.appendChild(spanAccessToken);
      div.appendChild(pAccessToken);
  
      const pRefreshToken = document.createElement("p");
      const btnSetRefreshToken = document.createElement("button");
      btnSetRefreshToken.innerHTML = "Set Refresh Token";
      btnSetRefreshToken.addEventListener("click", function (evt) {
        newRefreshToken = window.prompt("Enter the refresh token: ");
        if (newRefreshToken) {
          myTokenManagement.setTokens({
            accessToken: myTokenManagement.getAccessToken(),
            refreshToken: newRefreshToken,
            tokenType: myTokenManagement.getTokenType(),
            expiryDate: myTokenManagement.getExpiryDate(),
          });
        }
      });
      pRefreshToken.appendChild(btnSetRefreshToken);
      const btnGetPKCERefreshToken = document.createElement("button");
      btnGetPKCERefreshToken.innerHTML = "Get PKCE Refresh Token";
      btnGetPKCERefreshToken.addEventListener("click", function (evt) {
        const authorizationEndpoint = window.prompt("Enter the authorization endpoint:");
        myTokenManagement.retrieveTokenPKCERefresh({
          authorizationEndpoint: authorizationEndpoint,
        });
      });
      pRefreshToken.appendChild(btnGetPKCERefreshToken);
      const btnRefreshAccessToken = document.createElement("button");
      btnRefreshAccessToken.innerHTML = "Refresh Access Token";
      btnRefreshAccessToken.addEventListener("click", function (evt) {
        myTokenManagement.refreshAccessTokenPKCE();
      });
      pRefreshToken.appendChild(btnRefreshAccessToken);
      const spanRefreshToken = document.createElement("span");
      spanRefreshToken.append(myTokenManagement.getRefreshToken());
      myTokenManagement.setCallbackRefreshToken(function (strToken) {
        spanRefreshToken.innerHTML = "";
        spanRefreshToken.append(strToken);
      });
      pRefreshToken.appendChild(spanRefreshToken);
      div.appendChild(pRefreshToken);
      document.body.appendChild(div);
    }
    const btnCreate = document.createElement("button");
    btnCreate.innerHTML = "Create";
    btnCreate.addEventListener("click", function (evt) {
      const args = {
        clientId: inpClientId.value,
        tokenEndpoint: inpTokenEndpoint.value,
      };
      createTokenManagement(args);
    });
    document.body.appendChild(btnCreate);
    OAuth2.receivedTokens.then(function (args) {
      createTokenManagement(args);
    }).catch(function (error) {
      console.error(error);
    });
  } catch (e) {
    console.error(e);
  }
}
