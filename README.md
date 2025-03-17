# Experience Manager Rock Star 2025

Sample code for the [Experience Manager Rock Star 2025](https://rockstar.adobeevents.com/en/) contest.

## AEM EDS server-side integration with AEP AJO

AEM Edge Delivery Services customers can use their own CDN to deliver AEM content under their own domain. Cloudflare is one of the supported CDNs. Documentation on how to set up a Cloudflare worker can be found [here](https://www.aem.live/docs/byo-cdn-cloudflare-worker-setup). The initial code for the Cloudflare worker was taken from the [Adobe repository](https://raw.githubusercontent.com/adobe/helix-cloudflare-prod-worker-template/main/src/index.mjs) and then extended to support server-side personalization using AEP AJO. 
