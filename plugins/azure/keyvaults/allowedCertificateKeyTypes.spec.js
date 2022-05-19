var expect = require('chai').expect;
var auth = require('./allowedCertificateKeyTypes');

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
        key_props: { exportable: true, kty: 'RSA', key_size: 2048, reuse_key: false },
        secret_props: { contentType: 'application/x-pkcs12' },
        x509_props: {
            subject: 'CN=test.com',
            sans: [Object],
            ekus: [Array],
            key_usage: [Array],
            validity_months: 12,
            basic_constraints: [Object]
        },
        lifetime_actions: [ [Object] ],
        issuer: { name: 'Self' },
        attributes: { enabled: true, created: 1649758944, updated: 1649758944 }
    },
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
        lifetime_actions: [ [Object] ],
        issuer: { name: 'Self' },
        attributes: { enabled: true, created: 1649758944, updated: 1649758944 }
    },
    {
        id: 'https://testvault.vault.azure.net/certificates/test-cert/policy',
        secret_props: { contentType: 'application/x-pkcs12' },
        key_props: { exportable: true, kty: 'ECC', key_size: 2048, reuse_key: false },
        x509_props: {
            subject: 'CN=test.com',
            sans: [Object],
            ekus: [Array],
            key_usage: [Array],
            validity_months: 12,
            basic_constraints: [Object]
        },
        lifetime_actions: [ [Object] ],
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

describe('allowedCertificateKeyTypes', function() {
    describe('run', function() {
        it('should give passing result if no key vaults found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Key Vaults found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [], {}, {}), { allowed_certificate_key_types: 'rsa' }, callback);
        });

        it('should give unkown result if Unable to query for Key Vaults', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Key Vaults');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, null, {}, {}), { allowed_certificate_key_types: 'rsa' }, callback);
        });

        it('should give passing result if no key vault certificates found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Key Vault Certificates found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[0]], { "/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault": { data: [] } }, {}), { allowed_certificate_key_types: 'rsa' }, callback);
        });

        it('should give unkown result if unable to query for Key Vault Certificates', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Key Vault certificates');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[0]], null, {}), { allowed_certificate_key_types: 'rsa' }, callback);
        });

        it('should give unknown results if unable to query for certificate policy', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Certificate Policy');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[0]], { "/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault": { data: [certificates] } }, {}), { allowed_certificate_key_types: 'rsa' }, callback);
        });

        it('should give unknown results if Unable to list key type for Key Vault Certificate', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list key type for Key Vault Certificate');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[0]], { "/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault": { data: [certificates] } }, { data: [certificatePolicy[1]] } ), { allowed_certificate_key_types: 'rsa' }, callback);
        });

        it('should give passing result if certificate has allowed key type', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Certificate key type is RSA');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[0]], { "/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault": { data: [certificates] } }, { data: { ...certificatePolicy[0] } } ), { allowed_certificate_key_types: 'rsa' }, callback);
        });

        it('should give failing result if certificate does not have allowed key type', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Certificate key type is ECC');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            auth.run(createCache(null, [listVaults[0]], { "/subscriptions/abcdef123-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.KeyVault/vaults/testvault": { data: [certificates] } }, { data: { ...certificatePolicy[2] } } ), { allowed_certificate_key_types: 'rsa' }, callback);
        });
    })
});
