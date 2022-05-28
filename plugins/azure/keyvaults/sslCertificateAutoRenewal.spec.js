var expect = require('chai').expect;
var auth = require('./sslCertificateAutoRenewal');

const listVaults = [
    {
        "id": "/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault",
        "name": "testvault",
        "type": "Microsoft.KeyVault/vaults",
        "location": "eastus",
        "tags": {},
        "sku": {
            "family": "A",
            "name": "Standard"
        }
    }
];

const certificates = [
    {
        id: 'https://testvault.vault.azure.net/certificates/test-cert',
        x5t: 'wi16heNOLNuStvVprwu6rzs0_is',
        attributes: [Object],
        tags: {},
        subject: ''
    }
];

const certificatePolicy = [
    {
        id: 'https://testvault.vault.azure.net/certificates/test-cert/policy',
        secret_props: { contentType: 'application/x-pkcs12' },
        x509_props: {
            subject: 'CN=test.com',
            sans: [Object],
            ekus: [Array],
            key_usage: [Array],
            validity_months: 12,
            basic_constraints: [Object]
        },
        lifetime_actions: [   {
            trigger: { lifetime_percentage: 80 },
            action: { action_type: 'AutoRenew' }
          } ],
        issuer: { name: 'Self' },
        attributes: { enabled: true, created: 1649758944, updated: 1649758944 }
    },
    {
        id: 'https://testvault.vault.azure.net/certificates/test-cert/policy',
        secret_props: { contentType: 'application/x-pkcs12' },
        key_props: { exportable: true, kty: 'ECC', key_size: 1098, reuse_key: false },
        x509_props: {
            subject: 'CN=test.com',
            sans: [Object],
            ekus: [Array],
            key_usage: [Array],
            validity_months: 12,
            basic_constraints: [Object]
        },
        lifetime_actions: [   {
            trigger: { lifetime_percentage: 80 },
            action: { action_type: 'EmailContacts' }
          } ],
        issuer: { name: 'Self' },
        attributes: { enabled: true, created: 1649758944, updated: 1649758944 }
    }
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

describe('sslCertificateAutoRenewal', function() {
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

            auth.run(createCache(null, [listVaults[0]], { "/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault": { data: [] } }, {}), {}, callback);
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

            auth.run(createCache(null, [listVaults[0]], { "/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault": { data: [certificates] } }, {}), {}, callback);
        });

        it('should give passing result if SSL Certificate auto renewal is enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SSL Certificate auto renewal is enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[0]], { "/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault": { data: [certificates] } }, { data: { ...certificatePolicy[0] } } ), {}, callback);
        });

        it('should give failing result if SSL Certificate auto renewal is not enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SSL Certificate auto renewal is not enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[0]], { "/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault": { data: [certificates] } }, { data: { ...certificatePolicy[1] } } ), {}, callback);
        });
    })
});
