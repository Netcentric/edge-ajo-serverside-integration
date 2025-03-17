/*
 * Copyright 2022 Adobe. All rights reserved.
 * This file is licensed to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
 * OF ANY KIND, either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */

'use strict';

async function buildPayload(fpid, email, curentPageURL) {

  const identityMap = {};

  if (fpid) {
      identityMap.FPID = [
          {
              id: fpid,
              authenticatedState: "ambiguous",
              primary: !email
          }
      ];
  }

  if (email) {
      identityMap.Email = [
          {
              id: email,
              authenticatedState: "ambiguous",
              primary: true
          }
      ];
  }

  const payload = {
      "event": {
          "xdm": {
              identityMap,
              "eventType": "web.webpagedetails.pageViews",
              "web": {
                "webPageDetails": {
                  "URL": curentPageURL,
                }
              }
          }
      },
      "query": {
          "identity": {
            "fetch": [
                "ECID"
            ]
          },
          "personalization": {
              "schemas": [
                  "https://ns.adobe.com/personalization/default-content-item",
                  "https://ns.adobe.com/personalization/html-content-item",
                  "https://ns.adobe.com/personalization/json-content-item",
                  "https://ns.adobe.com/personalization/redirect-item",
                  "https://ns.adobe.com/personalization/dom-action"
              ],
              "decisionScopes": [
                  "__view__"
              ],
              "surfaces": [
                  "web://rockstar.moment-innovation.com/#rs-2025-ed-authenticated",
                  "web://rockstar.moment-innovation.com/#rs-2025-ed-unauthenticated",  
                  "web://rockstar.moment-innovation.com/#rs-2025-contentcard",
                  "web://rockstar.moment-innovation.com/#rs-2025-header-authenticated"
              ]
          }
      }
  };
  return payload;
}

async function callEdgeAPI(payload) {

  const edgeURL = 'https://edge.adobedc.net/ee/v2/interact?dataStreamId=ad0d1aec-b3e9-41e6-abec-fa5fa2990288'; 

  try {
      const response = await fetch(edgeURL, {
          method: 'POST',
          headers: {
              'Content-Type': 'application/json',
          },
          body: JSON.stringify(payload)
      });

      if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
      }
      
      const data = await response.json();
      return data;
  } catch (error) {
      console.error('Error calling Adobe Edge API:', error);
  }
}

function extractContent(jsonPayload, targetScope) {

  if (!jsonPayload) return [];

  // Find the personalization:decisions handle
  const decisionHandle = jsonPayload.handle.find(
    h => h.type === 'personalization:decisions'
  );
  
  if (!decisionHandle || !decisionHandle.payload) {
    return [];
  }

  // Find the payload item matching the scope
  const matchingPayload = decisionHandle.payload.find(
    p => p.scope === targetScope
  );

  if (!matchingPayload || !matchingPayload.items) {
    return [];
  }

  if (targetScope === 'web://rockstar.moment-innovation.com/#rs-2025-contentcard') {
    return matchingPayload.items.flatMap(item => {
      if (item.data && item.data.rules) {
        return item.data.rules.flatMap(rule => 
          rule.consequences.map(consequence => consequence.detail.data)
        );
      }
      return [];
    });
  }

  return matchingPayload.items.map(item => item.data);
}

function parseCookies(cookieHeader) {
  return Object.fromEntries(
    cookieHeader.split("; ").map((cookie) => {
      const [name, ...value] = cookie.split("=");
      return [name.trim(), value.join("=").trim()];
    })
  );
}

function generateUUID() {
  let d = new Date().getTime();
  
  // Use high-precision timer if available
  if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
    d += performance.now();
  }
  
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = (d + Math.random() * 16) % 16 | 0;
    d = Math.floor(d / 16);
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

function isPageRequest(request) {
    const acceptHeader = request.headers.get("Accept") || "";
    return acceptHeader.includes("text/html"); // && !acceptHeader.includes("image/");
}

const getExtension = (path) => {
  const basename = path.split('/').pop();
  const pos = basename.lastIndexOf('.');
  return (basename === '' || pos < 1) ? '' : basename.slice(pos + 1);
};

const isMediaRequest = (url) => /\/media_[0-9a-f]{40,}[/a-zA-Z0-9_-]*\.[0-9a-z]+$/.test(url.pathname);

const handleRequest = async (request, env, ctx) => {
  const url = new URL(request.url);
  if (url.port) {
    // Cloudflare opens a couple more ports than 443, so we redirect visitors
    // to the default port to avoid confusion. 
    // https://developers.cloudflare.com/fundamentals/reference/network-ports/#network-ports-compatible-with-cloudflares-proxy
    const redirectTo = new URL(request.url);
    redirectTo.port = '';
    return new Response('Moved permanently to ' + redirectTo.href, {
      status: 301,
      headers: {
        location: redirectTo.href
      }
    });
  }

  const extension = getExtension(url.pathname);

  // remember original search params
  const savedSearch = url.search;

  // sanitize search params
  const { searchParams } = url;
  if (isMediaRequest(url)) {
    for (const [key] of searchParams.entries()) {
      if (!['format', 'height', 'optimize', 'width'].includes(key)) {
        searchParams.delete(key);
      }
    }
  } else if (extension === 'json') {
    for (const [key] of searchParams.entries()) {
      if (!['limit', 'offset', 'sheet'].includes(key)) {
        searchParams.delete(key);
      }
    }
  } else {
    // neither media nor json request: strip search params
    url.search = '';
  }
  searchParams.sort();
  
  url.hostname = env.ORIGIN_HOSTNAME;
  if (!url.origin.match(/^https:\/\/rockstar2025--.*--.*\.(?:aem|hlx)\.live/)) {
    return new Response('Invalid ORIGIN_HOSTNAME', { status: 500 });
  }
  const req = new Request(url, request);
  req.headers.set('x-forwarded-host', req.headers.get('host'));
  req.headers.set('x-byo-cdn-type', 'cloudflare');
  if (env.PUSH_INVALIDATION) {
    req.headers.set('x-push-invalidation', 'enabled');
  }
  if (env.ORIGIN_AUTHENTICATION) {
    req.headers.set('authorization', `token ${env.ORIGIN_AUTHENTICATION}`);
  }
  let resp = await fetch(req, {
    cf: {
      // cf doesn't cache html by default: need to override the default behavior
      cacheEverything: true,
    },
  });

  if (request.method === "GET" && isPageRequest(request) && extension !== 'json') {

    let html = await resp.text();

    // Parse logged in user and FPD cookies
    const cookieHeader = request.headers.get("cookie") || "";
    const cookies = parseCookies(cookieHeader);
    const loggedUserEmail = cookies["ncUser"] || "";
    let fpdValue = cookies["FPD"] || generateUUID();

    const ajoPaylaod = await buildPayload(fpdValue, loggedUserEmail, request.url);
    const ajoData =  await callEdgeAPI(ajoPaylaod);

    const scopes = [
      'rs-2025-contentcard',
      'rs-2025-header-authenticated',
      'rs-2025-ed-authenticated'
    ];

    scopes.forEach(scope => {
      const scopeED = extractContent(ajoData, `web://rockstar.moment-innovation.com/#${scope}`);
      if (Array.isArray(scopeED) && scopeED.length > 0) {
        html = html.replace(new RegExp(`(${scope})`, 'g'), JSON.stringify(scopeED, null, 2));
      }
    });

    resp = new Response(html, resp);

    // Create FPD cookie if does not exists
    if (!cookies['FPD']) {
      // Set cookie with secure attributes
      const fpdCookieValue = [
        `FPD=${fpdValue}`,
        'Path=/',
        'Secure',
        'HttpOnly',
        'SameSite=Strict',
        // Set expiration to 1 year
        `Max-Age=${new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toUTCString()}`
      ].join('; ');

      resp.headers.set('Set-Cookie', fpdCookieValue);
    }
    else if (cookies['userchanged']) {
      // Remove FPD cookie. 
      resp.headers.append('Set-Cookie', "FPD=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure;");
      resp.headers.append('Set-Cookie', "userchanged=deleted; Path=/drafts/rockstar2025; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure;");
    }

    // Do not cache in the browser
    resp.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    resp.headers.set('Pragma', 'no-cache');
    resp.headers.set('Expires', '0');
  }
  else {
    resp = new Response(resp.body, resp);
  }  

  if (resp.status === 301 && savedSearch) {
    const location = resp.headers.get('location');
    if (location && !location.match(/\?.*$/)) {
      resp.headers.set('location', `${location}${savedSearch}`);
    }
  }
  resp.headers.delete('age');
  resp.headers.delete('x-robots-tag');
  return resp;
};

export default {
  fetch: handleRequest,
};
