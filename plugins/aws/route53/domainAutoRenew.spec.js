const expect = require('chai').expect;
var domainAutoRenew = require('./domainAutoRenew');

const domains = [
    {
        "DomainName": "test-domain.com",
        "AutoRenew" : true
    },
    {
        "DomainName": "test-domain.com",
        "AutoRenew" : false
    }
]


const createCache = (domain, domainErr) => {    
    return {
        route53domains: {
            listDomains: {
                'us-east-1': {
                    data: domain,
                    err: domainErr
                }
            },
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

describe('domainAutoRenew', function () {
    describe('run', function () {

        it('should PASS if Domain has auto renew enabled', function (done) {
            const cache = createCache([domains[0]]);
            domainAutoRenew.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('has auto renew enabled');
                done();
            });
        });

        it('should FAIL if Domain does not have auto renew enabled', function (done) {
            const cache = createCache([domains[1]]);
            domainAutoRenew.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                expect(results[0].message).to.include('does not have auto renew enabled');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for domains', function (done) {
            const cache = createCache([], {}, { message: 'Unable to query for domains' });
            domainAutoRenew.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for domains');
                done();
            });
        });


        it('should not return anything if list domains response not found', function (done) {
            const cache = createNullCache();
            domainAutoRenew.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});