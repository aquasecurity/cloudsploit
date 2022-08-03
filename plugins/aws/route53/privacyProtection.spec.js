const expect = require('chai').expect;
var privacyProtection = require('./privacyProtection');

const domains = [
    {
        "DomainName": "test-domain.com"
    }
]

const domainDetails = [
    {
        "DomainName": "test-domain.com",
        "RegistrantPrivacy": true 
    },
    {
        "DomainName": "test-domain.com",
        "RegistrantPrivacy": false 
    },
    {
        "DomainName": "test-domain.com",
    }
]

const createCache = (domain, detail, domainErr, detailErr) => {    
    if (domain && domain.length) var name = domain[0].DomainName;
    return {
        route53domains: {
            listDomains: {
                'us-east-1': {
                    data: domain,
                    err: domainErr
                }
            },
            getDomainDetail: {
                'us-east-1': {
                    [name]: {
                        data: detail,
                        err: detailErr
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        route53domains: {
            listDomains: {
                'us-east-1': null
            }
        }
    };
};

describe('privacyProtection', function () {
    describe('run', function () {

        it('should PASS if privacy protection enabled', function (done) {
            const cache = createCache([domains[0]], domainDetails[0]);
            privacyProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if privacy protection disabled', function (done) {
            const cache = createCache([domains[0]], domainDetails[1]);
            privacyProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if privacy property not found', function (done) {
            const cache = createCache([domains[0]], domainDetails[2]);
            privacyProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to list domains', function (done) {
            const cache = createCache([], {}, { message: 'Unable to list domains' });
            privacyProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });


        it('should not return anything if list domains response not found', function (done) {
            const cache = createNullCache();
            privacyProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});