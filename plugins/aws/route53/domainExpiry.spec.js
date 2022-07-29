const expect = require('chai').expect;
var domainExpiry = require('./domainExpiry');


var domainWarn = new Date();
domainWarn.setMonth(domainWarn.getMonth() + 1);
var domainPass = new Date();
domainPass.setMonth(domainPass.getMonth() + 2);
var domainFail = new Date();
domainFail.setMonth(domainFail.getMonth() - 1);

const domains = [
    {
        "DomainName": "example.com",
        "AutoRenew": true,
        "TransferLock": true,
        "Expiry": domainPass
    },
    {
        "DomainName": "example.com.ar",
        "AutoRenew": true,
        "TransferLock": true,
        "Expiry": domainPass
    },
    {
        "DomainName": "example.com",
        "AutoRenew": true,
        "TransferLock": false,
        "Expiry": domainFail
    },
    {
        "DomainName": "example.com.uk",
        "AutoRenew": true,
        "TransferLock": true
    },
];


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

describe('domainExpiry', function () {
    describe('run', function () {

        it('should PASS if Domain will expire', function (done) {
            const cache = createCache([domains[0]]);
            domainExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('expires in');
                done();
            });
        });

        it('should FAIL if Domain expired', function (done) {
            const cache = createCache([domains[2]]);
            domainExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('expired');
                done();
            });
        });

        it('should PASS if Domain will expire', function (done) {
            const cache = createCache([domains[1]]);
            domainExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('expires in');
                done();
            });
        });

        
        it('should UNKNOWN if Expiration for domain could not be determined', function (done) {
            const cache = createCache([domains[3]]);
            domainExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('could not be determined');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for domains', function (done) {
            const cache = createCache([], {}, { message: 'Unable to query for domains' });
            domainExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for domains');
                done();
            });
        });


        it('should not return anything if list domains response not found', function (done) {
            const cache = createNullCache();
            domainExpiry.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});