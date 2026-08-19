/**
 * Known brands and their legitimate sender domains.
 * Used for impersonation detection.
 */
const BRANDS = {
  paypal: ["paypal.com", "paypal.co.uk"],
  microsoft: ["microsoft.com", "outlook.com", "hotmail.com", "live.com", "office.com"],
  google: ["google.com", "gmail.com", "youtube.com"],
  apple: ["apple.com", "icloud.com"],
  amazon: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr"],
  facebook: ["facebook.com", "meta.com", "fb.com"],
  instagram: ["instagram.com"],
  netflix: ["netflix.com"],
  linkedin: ["linkedin.com"],
  twitter: ["twitter.com", "x.com"],
  dropbox: ["dropbox.com"],
  dhl: ["dhl.com", "dhl.de"],
  fedex: ["fedex.com"],
  ups: ["ups.com"],
  "bank of america": ["bankofamerica.com"],
  wellsfargo: ["wellsfargo.com"],
  chase: ["chase.com", "jpmorgan.com"],
  "wells fargo": ["wellsfargo.com"],
  docusign: ["docusign.com", "docusign.net"],
};

module.exports = { BRANDS };
