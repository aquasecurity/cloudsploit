var expect = require('chai').expect;
var securityContactsEnabled = require('./securityContactsEnabled');

const securityContacts = [
    {
        'id': '/subscriptions/123/providers/Microsoft.Security/securityContacts/contact1',
        'name': 'contact1'
    },
    {
        'id': '/subscriptions/123/providers/Microsoft.Security/securityContacts/contact1',
        'name': 'contact1',
        'email': 'test@test.com'
    },
    {
        'id': '/subscriptions/123/providers/Microsoft.Security/securityContacts/contact1',
        'name': 'contact1',
        'phone': '0123456789'
    },
    {
        'id': '/subscriptions/123/providers/Microsoft.Security/securityContacts/contact1',
        'name': 'contact1',
        'email': 'test@test.com',
        'phone': '0123456789'
    }
];

const createCache = (securityContacts) => {
    return {
        securityContacts: {
            list: {
                global:{
                    data: securityContacts
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        securityContacts: {
            list: {
                global: {}
            }
        }
    };
};

describe('securityContactsEnabled', function() {
    describe('run', function() {
        it('should give failing result if no security contacts', function(done) {
            const cache = createCache([]);
            securityContactsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing security contacts');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query for security contacts', function(done) {
            const cache = createErrorCache();
            securityContactsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for security contacts');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if security contact has both phone and email set', function(done) {
            const cache = createCache([securityContacts[3]]);
            securityContactsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                
                //Phone verification
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Security Contact phone number is set on the subscription');
                //Email verification
                expect(results[1].status).to.equal(0);
                expect(results[1].message).to.include('Security Contact email address is set on the subscription');
                
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result for missing phone number', function(done) {
            const cache = createCache([securityContacts[1]]);
            securityContactsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                
                //Phone verification
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Security Contact phone number is not set on the subscription');
                //Email verification
                expect(results[1].status).to.equal(0);
                expect(results[1].message).to.include('Security Contact email address is set on the subscription');
                
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result for missing email', function(done) {
            const cache = createCache([securityContacts[2]]);
            securityContactsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                
                //Phone verification
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Security Contact phone number is set on the subscription');
                //Email verification
                expect(results[1].status).to.equal(2);
                expect(results[1].message).to.include('Security Contact email address is not set on the subscription');
                
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result for missing email and phone number', function(done) {
            const cache = createCache([securityContacts[0]]);
            securityContactsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                
                //Phone verification
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Security Contact phone number is not set on the subscription');
                //Email verification
                expect(results[1].status).to.equal(2);
                expect(results[1].message).to.include('Security Contact email address is not set on the subscription');
                
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});