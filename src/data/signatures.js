/**
 * Tech stack detection signatures
 * Comprehensive database for identifying technologies
 */

export const SIGNATURES = {
  // ==================== EMAIL SERVICE PROVIDERS ====================
  esp: {
    // MX record patterns
    mx: {
      'Klaviyo': ['klaviyo-mail.com', 'klaviyomail.com'],
      'Mailchimp': ['mailchimp.com', 'mcsv.net', 'mcdlv.net'],
      'SendGrid': ['sendgrid.net', 'sendgrid.com'],
      'Mailgun': ['mailgun.org', 'mailgun.com'],
      'Postmark': ['postmarkapp.com', 'postmark.'],
      'Amazon SES': ['amazonses.com', 'amazonaws.com'],
      'Mandrill': ['mandrillapp.com'],
      'SparkPost': ['sparkpostmail.com', 'sparkpost.com'],
      'Sendinblue': ['sendinblue.com', 'sibmail.com'],
      'Brevo': ['brevo.com', 'sendinblue.com'],
      'Constant Contact': ['constantcontact.com', 'ctct.com'],
      'Campaign Monitor': ['cmail.', 'createsend.com'],
      'ActiveCampaign': ['acems.com', 'acdcmail.com', 'activehosted.com'],
      'HubSpot': ['hubspot.com', 'hubspotemail.net'],
      'Salesforce Marketing Cloud': ['exacttarget.com', 'salesforce.com'],
      'Iterable': ['iterable.com'],
      'Customer.io': ['customer.io', 'cio.email'],
      'Drip': ['drip.com', 'getdrip.com'],
      'ConvertKit': ['convertkit.com', 'ck.page'],
      'Omnisend': ['omnisend.com', 'omnisnds.com'],
      'Dotdigital': ['dotdigital.com', 'dotmailer.com'],
      'Emarsys': ['emarsys.com', 'emarsys.net'],
      'Sailthru': ['sailthru.com'],
      'Listrak': ['listrak.com'],
      'Cordial': ['cordial.io', 'cordialmail.com'],
      'Bluecore': ['bluecore.com', 'triggit.com'],
      'Attentive': ['attentive.com', 'attentivemobile.com'],
      'Yotpo': ['yotpo.com'],
      'Mailjet': ['mailjet.com'],
      'Zoho': ['zoho.com', 'zohomail.com'],
      'Google Workspace': ['google.com', 'googlemail.com', 'gmail.com'],
      'Microsoft 365': ['outlook.com', 'office365.com', 'microsoft.com'],
      'Proofpoint': ['pphosted.com', 'proofpoint.com'],
      'Mimecast': ['mimecast.com'],
      'Barracuda': ['barracudanetworks.com']
    },
    // TXT/SPF record patterns
    txt: {
      'Klaviyo': ['klaviyo', 'klaviyomail'],
      'Mailchimp': ['mailchimp', 'mcsv.net', 'mcdlv.net'],
      'SendGrid': ['sendgrid'],
      'Mailgun': ['mailgun'],
      'Postmark': ['postmark'],
      'Amazon SES': ['amazonses'],
      'Mandrill': ['mandrill'],
      'SparkPost': ['sparkpost'],
      'Sendinblue': ['sendinblue', 'sibmail'],
      'Brevo': ['brevo'],
      'Constant Contact': ['constantcontact', 'ctct'],
      'Campaign Monitor': ['createsend', 'cmail'],
      'ActiveCampaign': ['acdcmail', 'activehosted'],
      'HubSpot': ['hubspot'],
      'Salesforce Marketing Cloud': ['exacttarget', 'salesforce'],
      'Iterable': ['iterable'],
      'Customer.io': ['customer.io'],
      'Drip': ['getdrip'],
      'ConvertKit': ['convertkit'],
      'Omnisend': ['omnisend'],
      'Dotdigital': ['dotdigital', 'dotmailer'],
      'Emarsys': ['emarsys'],
      'Sailthru': ['sailthru'],
      'Listrak': ['listrak'],
      'Cordial': ['cordial'],
      'Bluecore': ['bluecore'],
      'Attentive': ['attentive'],
      'Yotpo': ['yotpo'],
      'Mailjet': ['mailjet'],
      'Zoho': ['zoho'],
      'Google Workspace': ['_spf.google.com', 'google.com'],
      'Microsoft 365': ['spf.protection.outlook', 'microsoft.com']
    },
    // CNAME patterns (tracking domains)
    cname: {
      'Klaviyo': ['klaviyo', 'klavio'],
      'Mailchimp': ['mailchimp', 'mcsv', 'mcdlv', 'list-manage'],
      'SendGrid': ['sendgrid'],
      'Mailgun': ['mailgun'],
      'Amazon SES': ['amazonses', 'ses.amazonaws'],
      'Postmark': ['postmark', 'pstmrk'],
      'Mandrill': ['mandrillapp', 'mandrill'],
      'SparkPost': ['sparkpost'],
      'Sendinblue': ['sendinblue', 'sib.'],
      'Brevo': ['brevo', 'brevoweb'],
      'Constant Contact': ['constantcontact', 'ctct', 'cc.'],
      'Campaign Monitor': ['createsend', 'cmail'],
      'ActiveCampaign': ['activehosted', 'acems', 'acdcmail', 'img.acems'],
      'HubSpot': ['hubspot', 'hs-analytics', 'track.hubspot'],
      'Salesforce Marketing Cloud': ['exacttarget', 'sfmc'],
      'Iterable': ['iterable'],
      'Customer.io': ['customer.io', 'cio.'],
      'Drip': ['getdrip', 'drip.'],
      'ConvertKit': ['convertkit', 'ck.page'],
      'Omnisend': ['omnisend', 'omnisnds'],
      'Dotdigital': ['dotdigital', 'dotmailer', 'trackedlink'],
      'Emarsys': ['emarsys'],
      'Sailthru': ['sailthru'],
      'Listrak': ['listrak'],
      'Cordial': ['cordial'],
      'Bluecore': ['bluecore', 'triggit'],
      'Attentive': ['attentive', 'attn'],
      'Yotpo': ['yotpo'],
      'Mailjet': ['mailjet'],
      'Ometria': ['ometria'],
      'Zaius': ['zaius'],
      'Rejoiner': ['rejoiner'],
      'Retention Science': ['retentionscience'],
      'Moosend': ['moosend'],
      'GetResponse': ['getresponse'],
      'AWeber': ['aweber'],
      'MailerLite': ['mailerlite'],
      'Benchmark Email': ['benchmark']
    },
    // Script src patterns
    script: {
      'Klaviyo': ['klaviyo.com', 'klav'],
      'Mailchimp': ['mailchimp.com', 'chimpstatic.com', 'mc.us'],
      'HubSpot': ['hs-scripts.com', 'hs-analytics', 'hubspot.com', 'hscollectedforms'],
      'ActiveCampaign': ['trackcmp.net', 'activehosted.com'],
      'Sendinblue': ['sibautomation.com', 'sendinblue.com'],
      'Brevo': ['brevo.com'],
      'Omnisend': ['omnisrc.com', 'omnisend.com'],
      'Drip': ['getdrip.com', 'dc.getdrip'],
      'ConvertKit': ['convertkit.com', 'convertflow'],
      'Customer.io': ['customer.io', 'cio.js'],
      'Iterable': ['iterable.com'],
      'Sailthru': ['sailthru.com'],
      'Listrak': ['listrak.com', 'listrakbi'],
      'Cordial': ['cordial.io'],
      'Bluecore': ['bluecore.com', 'triggit.com'],
      'Attentive': ['attentivemobile.com', 'attn.tv'],
      'Yotpo': ['yotpo.com', 'staticw2.yotpo'],
      'Dotdigital': ['dmtracking', 'dotdigital'],
      'Emarsys': ['emarsys.com', 'scarabresearch'],
      'Constant Contact': ['ctctcdn.com'],
      'Campaign Monitor': ['createsend1.com'],
      'GetResponse': ['getresponse.com'],
      'AWeber': ['aweber.com'],
      'MailerLite': ['mailerlite.com', 'ml.js'],
      'Moosend': ['moosend.com'],
      'Ometria': ['ometria.com']
    },
    // Inline script patterns
    inline: {
      'Klaviyo': ['klaviyo', '_learnq', 'klav'],
      'Mailchimp': ['mailchimp', 'mc_cid', 'mc_eid'],
      'HubSpot': ['hubspot', '_hsq', 'hs-cta'],
      'ActiveCampaign': ['activecampaign', 'vgo('],
      'Omnisend': ['omnisend', '_omnisend'],
      'Drip': ['_dcq', 'getdrip'],
      'ConvertKit': ['convertkit', 'ckSubscriber'],
      'Sendinblue': ['sendinblue', 'sib.', 'sibautomation'],
      'Brevo': ['brevo'],
      'Customer.io': ['customer.io', '_cio'],
      'Sailthru': ['sailthru', 'Sailthru.init'],
      'Listrak': ['listrak', '_ltk'],
      'Attentive': ['attentive', '__attentive'],
      'Yotpo': ['yotpo', 'yotpo_widget'],
      'Dotdigital': ['dmPt', 'dotdigital'],
      'Emarsys': ['scarab', 'emarsys']
    }
  },

  // ==================== ANALYTICS ====================
  analytics: {
    script: {
      'Google Analytics': ['google-analytics.com', 'googletagmanager.com/gtag', 'analytics.js', 'ga.js'],
      'Google Analytics 4': ['gtag', 'google-analytics.com/g/'],
      'Adobe Analytics': ['omtrdc.net', 'adobeanalytics', '2o7.net', 'demdex'],
      'Mixpanel': ['mixpanel.com', 'mxpnl.com'],
      'Amplitude': ['amplitude.com', 'cdn.amplitude'],
      'Heap': ['heap-analytics', 'heapanalytics.com'],
      'Segment': ['segment.com', 'segment.io', 'analytics.min.js'],
      'Hotjar': ['hotjar.com', 'static.hotjar'],
      'FullStory': ['fullstory.com', 'fullstory.js'],
      'Lucky Orange': ['luckyorange.com', 'd10lpsik1i8c69.cloudfront'],
      'Crazy Egg': ['crazyegg.com', 'cetrk'],
      'Mouseflow': ['mouseflow.com'],
      'LogRocket': ['logrocket.com', 'logrocket.io'],
      'Pendo': ['pendo.io'],
      'Plausible': ['plausible.io'],
      'Fathom': ['usefathom.com'],
      'Matomo': ['matomo.js', 'piwik.js'],
      'Clicky': ['clicky.com', 'static.getclicky'],
      'StatCounter': ['statcounter.com']
    }
  },

  // ==================== CHAT/SUPPORT ====================
  chat: {
    script: {
      'Intercom': ['intercom.io', 'intercomcdn.com', 'widget.intercom.io'],
      'Drift': ['drift.com', 'js.driftt.com'],
      'Zendesk': ['zendesk.com', 'zdassets.com', 'zopim.com'],
      'Freshdesk': ['freshdesk.com', 'freshchat'],
      'HubSpot Chat': ['js.hs-scripts.com', 'hubspot.com/conversations'],
      'LiveChat': ['livechat.com', 'livechatinc.com'],
      'Tawk.to': ['tawk.to', 'embed.tawk'],
      'Crisp': ['crisp.chat', 'client.crisp.chat'],
      'Olark': ['olark.com'],
      'Help Scout': ['helpscout.net', 'beacon-v2'],
      'Gorgias': ['gorgias.chat', 'gorgias.io'],
      'Kustomer': ['kustomer.com'],
      'Gladly': ['gladly.com'],
      'Front': ['frontapp.com'],
      'Tidio': ['tidio.co', 'tidiochat'],
      'Chaport': ['chaport.com'],
      'JivoChat': ['jivochat.com', 'jivosite.com'],
      'PureChat': ['purechat.com'],
      'SnapEngage': ['snapengage.com'],
      'Chatra': ['chatra.io'],
      'Acquire': ['acquire.io'],
      'Re:amaze': ['reamaze.com', 'reamaze.js']
    }
  },

  // ==================== MARKETING PIXELS ====================
  marketing: {
    script: {
      'Facebook Pixel': ['connect.facebook.net', 'facebook.com/tr', 'fbq('],
      'Google Ads': ['googleadservices.com', 'googleads.g.doubleclick', 'conversion.js'],
      'TikTok Pixel': ['analytics.tiktok.com', 'tiktok.com/i18n'],
      'Pinterest Tag': ['pintrk', 's.pinimg.com', 'ct.pinterest.com'],
      'LinkedIn Insight': ['snap.licdn.com', 'linkedin.com/px', 'lintrk'],
      'Twitter Pixel': ['static.ads-twitter.com', 'analytics.twitter.com'],
      'Snapchat Pixel': ['tr.snapchat.com', 'sc-static.net'],
      'Reddit Pixel': ['redditstatic.com', 'redditmedia.com'],
      'Criteo': ['criteo.com', 'criteo.net'],
      'AdRoll': ['adroll.com', 'd.adroll.com'],
      'Taboola': ['taboola.com', 'trc.taboola'],
      'Outbrain': ['outbrain.com', 'outbrainimg.com'],
      'Bing Ads': ['bat.bing.com', 'clarity.ms'],
      'Microsoft Clarity': ['clarity.ms'],
      'Yahoo': ['analytics.yahoo.com', 'sp.analytics.yahoo.com'],
      'Quora Pixel': ['quora.com/_/ad'],
      'Affiliate': ['shareasale.com', 'awin1.com', 'rakuten', 'impact.com', 'partnerize']
    }
  },

  // ==================== TAG MANAGERS ====================
  tagManager: {
    script: {
      'Google Tag Manager': ['googletagmanager.com/gtm', 'gtm.js'],
      'Adobe Launch': ['assets.adobedtm.com', 'launch-', '_satellite'],
      'Tealium': ['tealiumiq.com', 'tealium.com', 'utag.js'],
      'Segment': ['cdn.segment.com', 'analytics.js'],
      'Ensighten': ['ensighten.com'],
      'Signal': ['thebrighttag.com'],
      'TagCommander': ['tagcommander.com', 'commander1.com']
    }
  },

  // ==================== A/B TESTING ====================
  abTesting: {
    script: {
      'Optimizely': ['optimizely.com', 'optimizelycdn.com'],
      'VWO': ['visualwebsiteoptimizer.com', 'vwo.com'],
      'AB Tasty': ['abtasty.com', 'try.abtasty'],
      'Google Optimize': ['googleoptimize.com'],
      'Dynamic Yield': ['dynamicyield.com', 'dy.com'],
      'Kameleoon': ['kameleoon.com', 'kameleoon.eu'],
      'Convert': ['convert.com', 'convertexperiments'],
      'Unbounce': ['unbounce.com', 'd9hhrg4mnvzow.cloudfront'],
      'LaunchDarkly': ['launchdarkly.com'],
      'Split.io': ['split.io'],
      'Conductrics': ['conductrics.com']
    }
  },

  // ==================== PAYMENT ====================
  payment: {
    script: {
      'Stripe': ['js.stripe.com', 'stripe.com/v3'],
      'PayPal': ['paypal.com/sdk', 'paypalobjects.com'],
      'Braintree': ['braintreegateway.com', 'braintree-api'],
      'Square': ['squareup.com', 'square.com'],
      'Adyen': ['adyen.com', 'checkoutshopper'],
      'Klarna': ['klarna.com', 'klarna-payments'],
      'Afterpay': ['afterpay.com', 'afterpay.js'],
      'Affirm': ['affirm.com', 'cdn1.affirm.com'],
      'Sezzle': ['sezzle.com'],
      'Shopify Payments': ['checkout.shopify.com'],
      'Apple Pay': ['applepay.cdn-apple.com'],
      'Google Pay': ['pay.google.com']
    }
  },

  // ==================== CMS ====================
  cms: {
    meta: {
      'WordPress': ['wordpress', 'developer wordpress'],
      'Drupal': ['drupal'],
      'Joomla': ['joomla'],
      'Squarespace': ['squarespace'],
      'Wix': ['wix.com'],
      'Webflow': ['webflow'],
      'Ghost': ['ghost'],
      'Contentful': ['contentful'],
      'Prismic': ['prismic'],
      'Sanity': ['sanity'],
      'Strapi': ['strapi'],
      'HubSpot CMS': ['hubspot']
    },
    html: {
      'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
      'Drupal': ['drupal.js', '/sites/default/', 'drupal.settings'],
      'Joomla': ['/media/jui/', 'joomla'],
      'Squarespace': ['static.squarespace', 'squarespace-cdn'],
      'Wix': ['static.wixstatic.com', 'wix.com'],
      'Webflow': ['webflow.com', 'website-files'],
      'Ghost': ['ghost.io', 'ghost.org'],
      'Next.js': ['_next/static', '__NEXT_DATA__'],
      'Nuxt.js': ['_nuxt/', '__NUXT__'],
      'Gatsby': ['gatsby-'],
      'React': ['react', 'react-dom'],
      'Vue.js': ['vue.js', 'vue.min.js', 'vuejs'],
      'Angular': ['ng-version', 'angular']
    }
  },

  // ==================== E-COMMERCE ====================
  ecommerce: {
    meta: {
      'Shopify': ['shopify'],
      'BigCommerce': ['bigcommerce'],
      'Magento': ['magento'],
      'WooCommerce': ['woocommerce'],
      'Salesforce Commerce Cloud': ['demandware', 'salesforce commerce'],
      'PrestaShop': ['prestashop'],
      'OpenCart': ['opencart'],
      'Volusion': ['volusion']
    },
    html: {
      'Shopify': ['cdn.shopify.com', 'shopify.com', 'myshopify.com', 'shopify-cdn'],
      'BigCommerce': ['bigcommerce.com', 'bigcommercecdn'],
      'Magento': ['mage/', 'magento', '/static/frontend/', 'varien'],
      'WooCommerce': ['woocommerce', 'wc-'],
      'Salesforce Commerce Cloud': ['demandware', 'dwanalytics', 'sfcc'],
      'PrestaShop': ['prestashop', 'presta'],
      'OpenCart': ['opencart', 'catalog/view'],
      'Volusion': ['volusion', 'a248.e.akamai.net'],
      'Shopware': ['shopware'],
      'SAP Commerce Cloud': ['hybris'],
      'commercetools': ['commercetools'],
      'Adobe Commerce': ['magento', 'adobe.com/commerce']
    }
  },

  // ==================== CDN ====================
  cdn: {
    cname: {
      'Cloudflare': ['cloudflare', 'cdn.cloudflare'],
      'Fastly': ['fastly.net', 'fastlylb.net'],
      'Akamai': ['akamaiedge.net', 'akamai.net', 'akamaitechnologies', 'akamaihd.net'],
      'Amazon CloudFront': ['cloudfront.net', 'd1.awsstatic'],
      'Google Cloud CDN': ['googlesyndication', 'googleusercontent'],
      'Azure CDN': ['azureedge.net', 'azure.net'],
      'KeyCDN': ['keycdn.com', 'kxcdn.com'],
      'StackPath': ['stackpathcdn.com', 'stackpathdns.com'],
      'Bunny CDN': ['b-cdn.net', 'bunnycdn'],
      'Cloudinary': ['cloudinary.com', 'res.cloudinary'],
      'imgix': ['imgix.net'],
      'Netlify': ['netlify.app', 'netlify.com'],
      'Vercel': ['vercel.app', 'vercel-dns.com', 'now.sh'],
      'Edgecast': ['edgecast.net', 'edgecastcdn'],
      'Limelight': ['llnwd.net', 'limelight']
    },
    header: {
      'Cloudflare': ['cloudflare'],
      'Fastly': ['fastly'],
      'Akamai': ['akamai', 'akamaighost'],
      'Amazon CloudFront': ['cloudfront', 'amz-cf'],
      'Varnish': ['varnish'],
      'nginx': ['nginx'],
      'Netlify': ['netlify'],
      'Vercel': ['vercel']
    }
  },

  // ==================== CRM ====================
  crm: {
    script: {
      'Salesforce': ['salesforce.com', 'force.com', 'sfdc.com'],
      'HubSpot CRM': ['hs-scripts.com', 'hubspot.com', 'hs-analytics'],
      'Zoho CRM': ['zoho.com/crm', 'zohocrm'],
      'Pipedrive': ['pipedrive.com'],
      'Freshsales': ['freshsales.io', 'freshworks.com'],
      'Microsoft Dynamics': ['dynamics.com', 'crm.dynamics'],
      'Zendesk Sell': ['getbase.com', 'zendesk.com/sell'],
      'Copper': ['copper.com', 'prosperworks.com'],
      'Insightly': ['insightly.com'],
      'Nimble': ['nimble.com'],
      'Close': ['close.com', 'close.io'],
      'Monday CRM': ['monday.com'],
      'Keap': ['keap.com', 'infusionsoft.com'],
      'ActiveCampaign CRM': ['activecampaign.com'],
      'Nutshell': ['nutshell.com'],
      'Less Annoying CRM': ['lessannoyingcrm.com'],
      'Capsule': ['capsulecrm.com'],
      'Streak': ['streak.com'],
      'Agile CRM': ['agilecrm.com'],
      'SugarCRM': ['sugarcrm.com'],
      'Vtiger': ['vtiger.com'],
      'Bitrix24': ['bitrix24.com'],
      'ServiceNow': ['servicenow.com', 'service-now.com'],
      'Veeva CRM': ['veeva.com'],
      'Oracle CX': ['oracle.com/cx', 'eloqua.com', 'rightnow.com'],
      'SAP CRM': ['sap.com/crm', 'sapcrm']
    },
    inline: {
      'Salesforce': ['salesforce', 'sfdc', 'pardot'],
      'HubSpot CRM': ['hubspot', '_hsq', 'hs-cta'],
      'Zoho CRM': ['zohocrm', 'zoho.com/crm'],
      'Pipedrive': ['pipedrive'],
      'Freshsales': ['freshsales'],
      'ActiveCampaign CRM': ['activecampaign']
    },
    cname: {
      'Salesforce': ['salesforce.com', 'force.com', 'pardot.com'],
      'HubSpot CRM': ['hubspot.com', 'hs-sites.com'],
      'Marketo': ['marketo.com', 'mktoweb.com', 'mktossl.com'],
      'Pardot': ['pardot.com', 'go.pardot.com'],
      'Microsoft Dynamics': ['dynamics.com', 'crm.dynamics', 'd365'],
      'Zendesk': ['zendesk.com', 'zdassets.com'],
      'Freshsales': ['freshsales.io', 'freshworks.com'],
      'Pipedrive': ['pipedrive.com'],
      'ServiceNow': ['servicenow.com', 'service-now.com'],
      'Veeva CRM': ['veeva.com'],
      'SAP CRM': ['sap.com', 'sapcrm']
    },
    txt: {
      'Salesforce': ['salesforce', 'pardot'],
      'HubSpot CRM': ['hubspot'],
      'Marketo': ['marketo'],
      'Microsoft Dynamics': ['dynamics', 'dynamics365'],
      'Zendesk': ['zendesk'],
      'Freshsales': ['freshsales', 'freshworks'],
      'Pipedrive': ['pipedrive'],
      'ServiceNow': ['servicenow'],
      'SAP CRM': ['sap.com']
    }
  },

  // ==================== HOSTING ====================
  hosting: {
    cname: {
      'AWS': ['amazonaws.com', 'awsglobalaccelerator'],
      'Google Cloud': ['googlecloud', 'ghs.google', 'appspot.com'],
      'Azure': ['azurewebsites.net', 'azure.com', 'windowsazure'],
      'Heroku': ['heroku.com', 'herokuapp.com', 'herokudns.com'],
      'DigitalOcean': ['digitalocean.com', 'digitaloceanspaces'],
      'Netlify': ['netlify.app', 'netlify.com'],
      'Vercel': ['vercel.app', 'vercel.com', 'now.sh'],
      'Render': ['render.com', 'onrender.com'],
      'Railway': ['railway.app'],
      'Fly.io': ['fly.dev', 'fly.io'],
      'Shopify': ['myshopify.com'],
      'Squarespace': ['sqsp.com', 'squarespace.com'],
      'Wix': ['wixsite.com', 'wix-dns.com'],
      'Webflow': ['webflow.io', 'proxy.webflow.com'],
      'GitHub Pages': ['github.io', 'githubusercontent'],
      'GitLab Pages': ['gitlab.io'],
      'Pantheon': ['pantheonsite.io'],
      'WP Engine': ['wpengine.com', 'wpenginepowered.com'],
      'Kinsta': ['kinsta.cloud', 'kinsta.com'],
      'SiteGround': ['siteground.biz'],
      'Bluehost': ['bluehost.com'],
      'GoDaddy': ['godaddy.com', 'secureserver.net'],
      'Cloudways': ['cloudwaysapps.com'],
      'Hetzner': ['your-server.de', 'hetzner']
    }
  }
};
