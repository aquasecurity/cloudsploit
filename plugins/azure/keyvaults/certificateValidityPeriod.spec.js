var expect = require('chai').expect;
var certificateValidityPeriod = require('./certificateValidityPeriod');

const vaults = [
    {
        'name': 'test-vault',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.KeyVault/vaults/test-vault',
        'type': 'Microsoft.KeyVault/vaults',
        'location': 'eastus'
    }
];

const certificates = [
    {
        'id': 'https://test-vault.vault.azure.net/certificates/test-cert'
    }
];

const certificatePolicies = [
    {
        'id': 'https://test-vault.vault.azure.net/certificates/test-cert/policy',
        'x509_props': {
            'subject': 'CN=test.com',
            'validity_months': 12
        }
    },
    {
        'id': 'https://test-vault.vault.azure.net/certificates/test-cert/policy',
        'x509_props': {
            'subject': 'CN=test.com',
            'validity_months': 24
        }
    },
    {
        'id': 'https://test-vault.vault.azure.net/certificates/test-cert/policy',
        'x509_props': {
            'subject': 'CN=test.com'
        }
    }
];

const createCache = (vaults, certificates, certificatePolicy) => {
    const vaultId = vaults && vaults.length ? vaults[0].id : null;
    const certId = certificates && certificates.length ? certificates[0].id : null;
    const certPolicyObj = {};
    if (certId) {
        certPolicyObj[certId] = certificatePolicy ? { data: certificatePolicy } : {};
    }
    return {
        vaults: {
            list: {
                'eastus': {
                    data: vaults
                }
            },
            getCertificates: {
                'eastus': vaultId ? { [vaultId]: { data: certificates } } : {}
            }
        },
        getCertificatePolicy: {
            get: {
                'eastus': certPolicyObj
            }
        }
    };
};

const createErrorCache = () => {
    return {
        vaults: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('certificateValidityPeriod', function () {
    describe('run', function () {
        it('should give passing result if no Key Vaults found', function (done) {
            const cache = createCache([], null, null);
            certificateValidityPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Key Vaults found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Key Vaults', function (done) {
            const cache = createErrorCache();
            certificateValidityPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Key Vaults');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no certificates found', function (done) {
            const cache = createCache(vaults, [], null);
            certificateValidityPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Key Vault Certificates found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if validity period is within the configured limit', function (done) {
            const cache = createCache(vaults, certificates, certificatePolicies[0]);
            certificateValidityPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Certificate validity period is set to 12 months');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if validity period exceeds the configured limit', function (done) {
            const cache = createCache(vaults, certificates, certificatePolicies[1]);
            certificateValidityPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Certificate validity period is set to 24 months which is greater than 12');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if validity period cannot be determined', function (done) {
            const cache = createCache(vaults, certificates, certificatePolicies[2]);
            certificateValidityPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to determine certificate validity period');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for certificate policy', function (done) {
            const cache = createCache(vaults, certificates, null);
            certificateValidityPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Certificate Policy');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
