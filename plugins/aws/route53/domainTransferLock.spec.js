const expect = require('chai').expect;
var domainTransferLock = require('./domainTransferLock');

const domains = [
    {
        "DomainName": "example.com",
        "AutoRenew": true,
        "TransferLock": true,
        "Expiry": 1602712345.0
    },
    {
        "DomainName": "example.com.",
        "AutoRenew": true,
        "TransferLock": false,
        "Expiry": 1602712345.0
    },
    {
        "DomainName": "example.com.uk",
        "AutoRenew": true,
        "TransferLock": true,
        "Expiry": 1602712345.0
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

describe('domainTransferLock', function () {
    describe('run', function () {

        it('should PASS if Domain has the transfer lock enabled', function (done) {
            const cache = createCache([domains[0]]);
            domainTransferLock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('has the transfer lock enabled');
                done();
            });
        });

        it('should FAIL if Domain does not have the transfer lock enabled', function (done) {
            const cache = createCache([domains[1]]);
            domainTransferLock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have the transfer lock enabled');
                done();
            });
        });

        it('should PASS if Domain does not support transfer locks', function (done) {
            const cache = createCache([domains[2]]);
            domainTransferLock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('does not support transfer locks');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for domains', function (done) {
            const cache = createCache([], {}, { message: 'Unable to query for domains' });
            domainTransferLock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for domains');
                done();
            });
        });


        it('should not return anything if list domains response not found', function (done) {
            const cache = createNullCache();
            domainTransferLock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});