var expect = require('chai').expect;
var auth = require('./certificateAutoRenewalPeriod');

const listVaults = [
    {
        id: '/subscriptions/1234/resourceGroups/sadeedrg/providers/Microsoft.KeyVault/vaults/sadeedvault',
        name: 'sadeedvault',
        type: 'Microsoft.KeyVault/vaults',
        location: 'eastus',
        tags: {},
        sku: [Object],
        tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
        accessPolicies: [Array],
        enabledForDeployment: false,
        enabledForDiskEncryption: false,
        enabledForTemplateDeployment: false,
        enableSoftDelete: true,
        softDeleteRetentionInDays: 90,
        enableRbacAuthorization: false,
        vaultUri: 'https://sadeedvault.vault.azure.net/',
        provisioningState: 'Succeeded'
    }
];

const certificates = [
    {
    "id": "https://nauman-test.vault.azure.net/certificates/sadeeds",
    "x5t": "7Xh2YQWMOycbTYAI057H2fBS5f4",
    "attributes": {
        "enabled": true,
        "nbf": 1658837295,
        "exp": 1690373895,
        "created": 1658837895,
        "updated": 1658837895
    },
    "tags": {},
    "subject": ""
    }
];

const certificatePolicy = [
    {
        "id": "https://nauman-test.vault.azure.net/certificates/sadeeds/policy",
        "key_props": {
          "exportable": true,
          "kty": "RSA",
          "key_size": 2048,
          "reuse_key": false
        },
        "secret_props": {
          "contentType": "application/x-pkcs12"
        },
        "x509_props": {
          "subject": "CN=plugin",
          "sans": {
            "dns_names": []
          },
          "ekus": [
            "1.3.6.1.5.5.7.3.1",
            "1.3.6.1.5.5.7.3.2"
          ],
          "key_usage": [
            "digitalSignature",
            "keyEncipherment"
          ],
          "validity_months": 12,
          "basic_constraints": {
            "ca": false
          }
        },
        "lifetime_actions": [
          {
            "trigger": {
              "days_before_expiry": 30
            },
            "action": {
              "action_type": "AutoRenew"
            }
          }
        ],
        "issuer": {
          "name": "Self"
        },
        "attributes": {
          "enabled": true,
          "created": 1658837891,
          "updated": 1658837891
        }
    },
    {
        "id": "https://nauman-test.vault.azure.net/certificates/sadeeds/policy",
        "key_props": {
          "exportable": true,
          "kty": "RSA",
          "key_size": 2048,
          "reuse_key": false
        },
        "secret_props": {
          "contentType": "application/x-pkcs12"
        },
        "x509_props": {
          "subject": "CN=plugin",
          "sans": {
            "dns_names": []
          },
          "ekus": [
            "1.3.6.1.5.5.7.3.1",
            "1.3.6.1.5.5.7.3.2"
          ],
          "key_usage": [
            "digitalSignature",
            "keyEncipherment"
          ],
          "validity_months": 12,
          "basic_constraints": {
            "ca": false
          }
        },
        "lifetime_actions": [
          {
            "trigger": {
              "days_before_expiry": 30
            },
            "action": {
              "action_type": "AutoRenew"
            }
          }
        ],
        "issuer": {
          "name": "Self"
        },
        "attributes": {
          "enabled": true,
          "created": 1658837891,
          "updated": 1658837891
        }
    },
    
    {
        "id": "https://nauman-test.vault.azure.net/certificates/sadeeds/policy",
        "key_props": {
          "exportable": true,
          "kty": "RSA",
          "key_size": 2048,
          "reuse_key": false
        },
        "secret_props": {
          "contentType": "application/x-pkcs12"
        },
        "x509_props": {
          "subject": "CN=plugin",
          "sans": {
            "dns_names": []
          },
          "ekus": [
            "1.3.6.1.5.5.7.3.1",
            "1.3.6.1.5.5.7.3.2"
          ],
          "key_usage": [
            "digitalSignature",
            "keyEncipherment"
          ],
          "validity_months": 12,
          "basic_constraints": {
            "ca": false
          }
        },
        "lifetime_actions": [
          {
            "trigger": {
              "lifetime_percentage": 80
            },
            "action": {
              "action_type": "AutoRenew"
            }
          }
        ],
        "issuer": {
          "name": "Self"
        },
        "attributes": {
          "enabled": true,
          "created": 1658837891,
          "updated": 1658837891
        }
    },
];

const createCache = (err, list, certs, getCertificatePolicy) => {
    return {
        vaults: {
            list: {
                'eastus': {
                    err: err,
                    data: list
                }
            },
            getCertificates: {
                'eastus': certs
            }
        },
        getCertificatePolicy: {
            get: {
                'eastus': getCertificatePolicy
            }
        }
    }
};

describe('certificateAutoRenewalPeriod', function() {
    describe('run', function() {
        it('should give passing result if no key vaults found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Key Vaults found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [], {}, {}), {}, callback);
        });

        it('should give unkown result if Unable to query for Key Vaults', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Key Vaults');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, null, {}, {}), {}, callback);
        });

        it('should give passing result if no key vault certificates found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Key Vault Certificates found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[0]], { "/subscriptions/1234/resourceGroups/sadeedrg/providers/Microsoft.KeyVault/vaults/sadeedvault": { data: [] } }, {}), {}, callback);
        });

        it('should give unkown result if unable to query for Key Vault Certificates', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Key Vault certificates');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[0]], null, {}), {}, callback);
        });

        it('should give unknown results if unable to query for certificate policy', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Certificate Policy');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[0]], { "/subscriptions/1234/resourceGroups/sadeedrg/providers/Microsoft.KeyVault/vaults/sadeedvault": { data: [certificates] } }, {}), {}, callback);
        });

        it('should give passing result if SSL Certificate has more days than expiry days to trigger auto renewal process', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SSL Certificate has');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[0]], { "/subscriptions/1234/resourceGroups/sadeedrg/providers/Microsoft.KeyVault/vaults/sadeedvault": { data: [certificates] } }, { data: { ...certificatePolicy[0] } } ), {key_vault_certificate_expiry_days: '31'}, callback);
        });

        it('should give failing result if SSL Certificate has less days than expiry days to trigger auto renewal process', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SSL Certificate has less');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[0]], { "/subscriptions/1234/resourceGroups/sadeedrg/providers/Microsoft.KeyVault/vaults/sadeedvault": { data: [certificates] } }, { data: { ...certificatePolicy[1] } } ), {key_vault_certificate_expiry_days: '29'}, callback);
        });

        it('should give passing result if SSL SSL Certificate auto renewal period is not enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SSL Certificate auto renewal period is not enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[0]], { "/subscriptions/1234/resourceGroups/sadeedrg/providers/Microsoft.KeyVault/vaults/sadeedvault": { data: [certificates] } }, { data: { ...certificatePolicy[2] } } ), {}, callback);
        });
    })
});
